-- Your SQL goes here
CREATE TABLE infos (
    user_id INTEGER PRIMARY KEY,
    full_name TEXT,
    address TEXT,
    age INTEGER,
    country TEXT,
    dog_name TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
