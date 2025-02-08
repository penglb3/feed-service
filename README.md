# Asynchronous Feed-Service

## Requirements
- Ubuntu 22.04
- GCC 11
- CMake >= 3.18
- Boost >= 1.84.0

## Install
### Install boost
We use boost.mysql and boost.redis to connect to mysql and redis.
```bash
wget https://archives.boost.io/release/1.87.0/source/boost_1_87_0.tar.gz
tar -xzf boost_1_87_0.tar.gz
cd boost_1_87_0
./bootstrap.sh
sudo ./b2 install
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
- [x] Testing
  - [x] Basic functionality
  - [ ] Smoke test / Error handling
  - [ ] Stress test
- [ ] Connection pool
- [ ] Distributed service
- [ ] Micro-service + Message Queue