# Asynchronous Feed-Service

## Requirements
- Ubuntu 22.04
- GCC >= 11 (we use c++20 coroutine)
- CMake >= 3.18
- Boost >= 1.84.0

## Install
### Install boost
This project relies on many submodules of boost (json, redis, mysql, asio for async framework & network, beast for http).
```bash
wget https://archives.boost.io/release/1.87.0/source/boost_1_87_0.tar.gz
tar -xzf boost_1_87_0.tar.gz
cd boost_1_87_0
./bootstrap.sh
sudo ./b2 install
```

## Building
`cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo && cmake --build build`

## Using
### Client side
Include `include/client.h` and compile your app with `src/http_client.cc`

### Server side
Run `build/feed-service <listen_ip> <listen_port> <config_file> <num_of_threads>`. See the `conf/config.json` for all configurable options w.r.t. MySQL and Redis.

For example: `build/feed-service 0.0.0.0 12345 conf/config.json 8`.

## Testing
Run `build/basic_function`, a print of 4 posts finally is expected. Exaple output:
```
#0: {"id":1,"user_id":1,"content":"hello user1","created_at":1741109720521043}
#1: {"id":2,"user_id":1,"content":"another post!","created_at":1741109720561550}
#2: {"id":3,"user_id":2,"content":"hello user2","created_at":1741109720668543}
#3: {"id":4,"user_id":3,"content":"hello user3","created_at":1741109720796941}
```

## API List
- [x] `POST /api/register {"username": ..., "password_hash": ...} -> user_id"`
- [x] `POST /api/login {"username": ..., "password_hash": ...} -> user_id`
- [x] `GET /api/follow/{user_id} -> List of user_id`
- [x] `POST /api/follow/{user_id} {"username": ...} -> user_id`
- [x] `GET /api/posts/{username | user_id} -> List of post`
- [x] `POST /api/post/ {"user_id":..., "content": ...} -> bool`
- [x] `GET /api/feed/{user_id} -> List of post`

## TODO List
- [x] Async framework
- [x] MySQL connection, async
- [x] Redis connection, async
- [x] Multi-threading
- [x] API and processing logic
- [x] SSL handshake
- [x] JSON Web Token for user id authorization
- [x] Testing
  - [x] Basic functionality
  - [ ] Smoke test / Error handling
  - [ ] Stress test
- [ ] Reusing established network connection
- [ ] Connection pool for MySQL and Redis
- [ ] Distributed service