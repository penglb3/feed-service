USE test_db;
TRUNCATE TABLE posts;
TRUNCATE TABLE follows;
SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE users;
SET FOREIGN_KEY_CHECKS = 1;