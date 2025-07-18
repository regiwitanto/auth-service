-- Password is 'admin123' hashed with bcrypt
INSERT INTO users (email, username, password, first_name, last_name, role, active, created_at, updated_at)
VALUES 
('admin@example.com', 'admin', '$2a$10$FcOiKJ4N1aYgiWWC0d1NpuMDjv74Wc4dxYY2Em8cQsmMM3NqVk3Ny', 'Admin', 'User', 'admin', true, NOW(), NOW())
ON CONFLICT (email) DO NOTHING;
