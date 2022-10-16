/*
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <linux/types.h>
#include <linux/perf_event.h>

#include "libbpf.h"
#include "perf_reader.h"

enum {
  RB_NOT_USED = 0, // ring buffer not usd
  RB_USED_IN_MUNMAP = 1, // used in munmap
  RB_USED_IN_READ = 2, // used in read
};

struct perf_reader * perf_reader_new(perf_reader_raw_cb raw_cb,
                                     perf_reader_lost_cb lost_cb,
                                     void *cb_cookie, int page_cnt) {
  struct perf_reader *reader = calloc(1, sizeof(struct perf_reader));
  if (!reader)
    return NULL;
  reader->raw_cb = raw_cb;
  reader->lost_cb = lost_cb;
  reader->cb_cookie = cb_cookie;
  reader->fd = -1;
  reader->page_size = getpagesize();
  reader->page_cnt = page_cnt;
  reader->is_unwind_call_stack = false;
  return reader;
}

void perf_reader_free(void *ptr) {
  if (ptr) {
    struct perf_reader *reader = ptr;
    pid_t tid = syscall(__NR_gettid);
    while (!__sync_bool_compare_and_swap(&reader->rb_use_state, RB_NOT_USED, RB_USED_IN_MUNMAP)) {
      // If the same thread, it is called from call back handler, no locking needed
      if (tid == reader->rb_read_tid)
        break;
    }
    munmap(reader->base, reader->page_size * (reader->page_cnt + 1));
    if (reader->fd >= 0) {
      ioctl(reader->fd, PERF_EVENT_IOC_DISABLE, 0);
      close(reader->fd);
    }
    free(reader->buf);
    free(ptr);
  }
}

int perf_reader_mmap(struct perf_reader *reader) {
  int mmap_size = reader->page_size * (reader->page_cnt + 1);

  if (reader->fd < 0) {
    fprintf(stderr, "%s: reader fd is not set\n", __FUNCTION__);
    return -1;
  }

  reader->base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, reader->fd, 0);
  if (reader->base == MAP_FAILED) {
    perror("mmap");
    return -1;
  }

  return 0;
}

struct perf_sample_trace_common {
  uint16_t id;
  uint8_t flags;
  uint8_t preempt_count;
  int pid;
};

struct perf_sample_trace_kprobe {
  struct perf_sample_trace_common common;
  uint64_t ip;
};

bool ReadFully(int fd, void* data, size_t byte_count) {
  uint8_t* p = (uint8_t*)data;
  size_t remaining = byte_count;
  while (remaining > 0) {
    ssize_t n = read(fd, p, remaining);
    if (n <= 0) return false;
    p += n;
    remaining -= n;
  }
  return true;
}

bool WriteFully(int fd, void* data, size_t byte_count) {
  uint8_t* p = (uint8_t*)data;
  size_t remaining = byte_count;
  while (remaining > 0) {
    ssize_t n = write(fd, p, remaining);
    if (n == -1) return false;
    p += n;
    remaining -= n;
  }
  return true;
}

static void print_frame_info(int pid, uint8_t *ptr, int write_size) {
  fprintf(stderr, "[%s] %d %p %d\n", __FUNCTION__, pid, ptr, write_size);

  int fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd == -1) {
    fprintf(stderr, "cannot socket()!\n");
  }
  const char *socket_path = "/dev/socket/mysock";
  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path));
 
  int ret = connect(fd, (struct sockaddr *)(&addr), sizeof(addr));
  if (ret != 0) {
    fprintf(stderr, "connect() to %s failed: %s\n", socket_path, strerror(errno));
  } else {
    WriteFully(fd, &pid, 4);
    // write_size += 4;
    WriteFully(fd, &write_size, 4);
 
    if (!WriteFully(fd, ptr, write_size)) {
      fprintf(stderr, "prepare to write %d bytes to socket\n", write_size);
      close(fd);
      return;
    }
    int frameinfo_size;
    if (ReadFully(fd, &frameinfo_size, 4)) {
      unsigned char frame_info[frameinfo_size + 1];
      if (ReadFully(fd, frame_info, frameinfo_size)) {
        frame_info[frameinfo_size] = '\0';
        printf("===================================>Frame:\n");
        printf("%s\n", frame_info);
      } else {
        fprintf(stderr, "Read frame_info from socket error.\n");
      }
    } else {
      fprintf(stderr, "Read frameinfo_size from socket error.\n");
    }
    // fprintf(stderr, "Read frame_info from socket placeholder.\n");
    close(fd);
  }
}

static void parse_sw(struct perf_reader *reader, void *data, int size) {
  uint8_t *ptr = data;
  struct perf_event_header *header = (void *)data;

    // struct {
    //     struct perf_event_header header;
    //     u32    size;               /* if PERF_SAMPLE_RAW */
    //     char   data[size];         /* if PERF_SAMPLE_RAW */
    //     u64    abi;                /* if PERF_SAMPLE_REGS_USER */
    //     u64    regs[weight(mask)]; /* if PERF_SAMPLE_REGS_USER */
    //     u64    size;               /* if PERF_SAMPLE_STACK_USER */
    //     char   data[size];         /* if PERF_SAMPLE_STACK_USER */
    //     u64    dyn_size;           /* if PERF_SAMPLE_STACK_USER && size != 0 */
    // };

  struct {
      uint32_t size;
      char data[0];
  } *raw = NULL;

  ptr += sizeof(*header);
  if (ptr > (uint8_t *)data + size) {
    fprintf(stderr, "%s: corrupt sample header\n", __FUNCTION__);
    return;
  }

  raw = (void *)ptr;
  ptr += sizeof(raw->size) + raw->size;
  if (ptr > (uint8_t *)data + size) {
    fprintf(stderr, "%s: corrupt raw sample\n", __FUNCTION__);
    return;
  }

  if (reader->is_unwind_call_stack) {
    // 这里要和bpf代码里面传递的数据结构一致
    int pid = *(int *)raw->data;
    // 这里的 size 是 perf_submit 传递的那个大小
    // 这里的 data 是整个传递的数据 也就是 PERF_SAMPLE_RAW 部分
    // 到此处 ptr 也就是 PERF_SAMPLE_RAW 结尾
    // 也就是说 write_size 是 PERF_SAMPLE_REGS_USER 和 PERF_SAMPLE_STACK_USER 的整个大小
    int write_size = ((uint8_t *)data + size) - ptr;
    print_frame_info(pid, ptr, write_size);
  }

  // enum perf_sample_regs_abi {
  //   PERF_SAMPLE_REGS_ABI_NONE = 0,
  //   PERF_SAMPLE_REGS_ABI_32 = 1,
  //   PERF_SAMPLE_REGS_ABI_64 = 2,
  // };

  // struct {
  //     uint64_t abi;
  //     uint64_t regs[33];
  // } *user_regs = NULL;
  // user_regs = (void *)ptr;
  // ptr += 8 + 8 * 33;
  // fprintf(stderr, "[%s] pid=%d abi=%lu\n", __FUNCTION__, *(int *)raw->data, user_regs->abi);

  // struct {
  //     uint64_t size;
  //     // 这个是 bcc 里面预设的固定值 sample_stack_user
  //     char data[16384];
  //     uint64_t dyn_size;
  // } *user_stack = NULL;
  // user_stack = (void *)ptr;
  // ptr += 8 + user_stack->size + 8;
  // fprintf(stderr, "[%s] size=%lu dyn_size=%lu\n", __FUNCTION__, user_stack->size, user_stack->dyn_size);

  if (reader->is_unwind_call_stack) {
    // hack ptr
    ptr += 16672;
  }
  // sanity check
  if (ptr != (uint8_t *)data + size) {
    fprintf(stderr, "%s: extra data at end of sample\n", __FUNCTION__);
    return;
  }

  if (reader->raw_cb)
    reader->raw_cb(reader->cb_cookie, raw->data, raw->size);
}

static uint64_t read_data_head(volatile struct perf_event_mmap_page *perf_header) {
  uint64_t data_head = perf_header->data_head;
  asm volatile("" ::: "memory");
  return data_head;
}

static void write_data_tail(volatile struct perf_event_mmap_page *perf_header, uint64_t data_tail) {
  asm volatile("" ::: "memory");
  perf_header->data_tail = data_tail;
}

void perf_reader_event_read(struct perf_reader *reader) {
  volatile struct perf_event_mmap_page *perf_header = reader->base;
  uint64_t buffer_size = (uint64_t)reader->page_size * reader->page_cnt;
  uint64_t data_head;
  uint8_t *base = (uint8_t *)reader->base + reader->page_size;
  uint8_t *sentinel = (uint8_t *)reader->base + buffer_size + reader->page_size;
  uint8_t *begin, *end;

  reader->rb_read_tid = syscall(__NR_gettid);
  if (!__sync_bool_compare_and_swap(&reader->rb_use_state, RB_NOT_USED, RB_USED_IN_READ))
    return;

  // Consume all the events on this ring, calling the cb function for each one.
  // The message may fall on the ring boundary, in which case copy the message
  // into a malloced buffer.
  for (data_head = read_data_head(perf_header); perf_header->data_tail != data_head;
      data_head = read_data_head(perf_header)) {
    uint64_t data_tail = perf_header->data_tail;
    uint8_t *ptr;

    begin = base + data_tail % buffer_size;
    // event header is u64, won't wrap
    struct perf_event_header *e = (void *)begin;
    ptr = begin;
    end = base + (data_tail + e->size) % buffer_size;
    if (end < begin) {
      // perf event wraps around the ring, make a contiguous copy
      reader->buf = realloc(reader->buf, e->size);
      size_t len = sentinel - begin;
      memcpy(reader->buf, begin, len);
      memcpy((void *)((unsigned long)reader->buf + len), base, e->size - len);
      ptr = reader->buf;
    }

    if (e->type == PERF_RECORD_LOST) {
      /*
       * struct {
       *    struct perf_event_header    header;
       *    u64                id;
       *    u64                lost;
       *    struct sample_id        sample_id;
       * };
       */
      uint64_t lost = *(uint64_t *)(ptr + sizeof(*e) + sizeof(uint64_t));
      if (reader->lost_cb) {
        reader->lost_cb(reader->cb_cookie, lost);
      } else {
        fprintf(stderr, "Possibly lost %" PRIu64 " samples\n", lost);
      }
    } else if (e->type == PERF_RECORD_SAMPLE) {
      parse_sw(reader, ptr, e->size);
    } else {
      fprintf(stderr, "%s: unknown sample type %d\n", __FUNCTION__, e->type);
    }

    write_data_tail(perf_header, perf_header->data_tail + e->size);
  }
  reader->rb_use_state = RB_NOT_USED;
  __sync_synchronize();
  reader->rb_read_tid = 0;
}

int perf_reader_poll(int num_readers, struct perf_reader **readers, int timeout) {
  struct pollfd pfds[num_readers];
  int i;

  for (i = 0; i <num_readers; ++i) {
    pfds[i].fd = readers[i]->fd;
    pfds[i].events = POLLIN;
  }

  if (poll(pfds, num_readers, timeout) > 0) {
    for (i = 0; i < num_readers; ++i) {
      if (pfds[i].revents & POLLIN)
        perf_reader_event_read(readers[i]);
    }
  }
  return 0;
}

int perf_reader_consume(int num_readers, struct perf_reader **readers) {
  int i;
  for (i = 0; i < num_readers; ++i) {
    perf_reader_event_read(readers[i]);
  }
  return 0;
}

void perf_reader_set_fd(struct perf_reader *reader, int fd) {
  reader->fd = fd;
}

int perf_reader_fd(struct perf_reader *reader) {
  return reader->fd;
}
