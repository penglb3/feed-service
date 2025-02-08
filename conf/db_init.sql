CREATE DATABASE test_db;
USE DATABASE test_db;

-- 用户表
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE,
    password_hash VARCHAR(64)
);

-- 帖子表
CREATE TABLE posts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 关注关系表
CREATE TABLE follows (
    follower_id INT,
    followee_id INT,
    PRIMARY KEY (follower_id, followee_id),
    FOREIGN KEY (follower_id) REFERENCES users(id),
    FOREIGN KEY (followee_id) REFERENCES users(id)
);

CREATE INDEX follows_followee ON follows (followee_id);
CREATE INDEX posts_user_id ON posts (user_id);