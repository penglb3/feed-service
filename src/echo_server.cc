#include <liburing/io_service.hpp>
#include <netinet/in.h>
#include <numeric>
#include <iostream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#define USE_SPLICE 0
#define USE_LINK 0
#define USE_POLL 0


enum {
  BUF_SIZE = 512,
  MAX_CONN_SIZE = 512,
};

int runningCoroutines = 0;

uio::task<> accept_connection(uio::io_service &service, int serverfd) {
  while (int clientfd = co_await service.accept(serverfd, nullptr, nullptr)) {
    [](uio::io_service &service, int clientfd) -> uio::task<> {
      printf("sockfd %d is accepted; number of running coroutines: %d\n",
             clientfd, ++runningCoroutines);
#if USE_SPLICE
      int pipefds[2];
      pipe(pipefds) | panic_on_err("pipe", true);
      on_scope_exit([&] {
        close(pipefds[0]);
        close(pipefds[1]);
      });
#else
      std::vector<char> buf(BUF_SIZE);
#endif
      while (true) {
#if USE_POLL
  #if USE_LINK
        service.poll(clientfd, POLLIN, IOSQE_IO_LINK);
  #else
        co_await service.poll(clientfd, POLLIN);
  #endif
#endif
#if USE_SPLICE
  #if USE_LINK
        service.splice(clientfd, -1, pipefds[1], -1, -1, SPLICE_F_MOVE,
                       IOSQE_IO_HARDLINK);
        int r = co_await service.splice(pipefds[0], -1, clientfd, -1, -1,
                                        SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (r <= 0)
          break;
  #else
        int r = co_await service.splice(clientfd, -1, pipefds[1], -1, -1,
                                        SPLICE_F_MOVE);
        if (r <= 0)
          break;
        co_await service.splice(pipefds[0], -1, clientfd, -1, r, SPLICE_F_MOVE);
  #endif
#else
  #if USE_LINK
    #error                                                                     \
        "This won't work because short read of IORING_OP_RECV is not considered an error"
  #else
        int r =
            co_await service.recv(clientfd, buf.data(), BUF_SIZE, MSG_NOSIGNAL);
        if (r <= 0) {
          break;
        }
        __kernel_timespec ts{1, 0};
        co_await service.timeout(&ts, 0);
        co_await service.send(clientfd, buf.data(), r, MSG_NOSIGNAL);
  #endif
#endif
      }
      service.shutdown(clientfd, SHUT_RDWR, IOSQE_IO_LINK);
      co_await service.close(clientfd);
      printf("sockfd %d is closed; number of running coroutines: %d\n",
             clientfd, --runningCoroutines);
    }(service, clientfd);
  }
}



int main(int argc, char *argv[]) {
  using uio::io_service;
  using uio::on_scope_exit;
  using uio::panic;
  using uio::panic_on_err;

  uint16_t server_port = 0;
  if (argc == 2) {
    server_port = static_cast<uint16_t>(std::strtoul(argv[1], nullptr, 10));
  }
  if (server_port == 0) {
    printf("Usage: %s <PORT>\n", argv[0]);
    return 1;
  }

  io_service service(MAX_CONN_SIZE);

  int sockfd =
      socket(AF_INET, SOCK_STREAM, 0) | panic_on_err("socket creation", true);
  on_scope_exit closesock([=]() { shutdown(sockfd, SHUT_RDWR); });

  if (sockaddr_in addr =
          {
              .sin_family = AF_INET,
              .sin_port = htons(server_port),
              .sin_addr = {INADDR_ANY},
              .sin_zero = {},
          };
      bind(sockfd, reinterpret_cast<sockaddr *>(&addr), sizeof(sockaddr_in))) {
    panic("socket binding", errno);
  }

  if (listen(sockfd, MAX_CONN_SIZE * 2) != 0) {
    panic("listen", errno);
  }
  printf("Listening: %d\n", server_port);

  service.run(accept_connection(service, sockfd));
}