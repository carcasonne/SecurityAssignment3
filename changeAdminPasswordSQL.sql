-- change password of first user
UPDATE users
SET username = 'fuck you',
    password = 'fuck you too'
WHERE id = 1;

UPDATE users
SET username = 'you will never guess this password',
    password = 'you will never guess this username'
WHERE id = 2;