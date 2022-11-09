-- change password of first user
UPDATE users
SET username = 'fuck you',
    password = 'fuck you too'
WHERE id = 1;

UPDATE users
SET username = 'Deniz Isler',
    password = 'DenizIsler89'
WHERE id = 2;