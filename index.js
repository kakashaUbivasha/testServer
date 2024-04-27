const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken'); // Подключаем библиотеку для работы с JWT
const { v4: uuidv4 } = require('uuid');
const app = express();
const PORT = 3000;
const crypto = require('crypto');
const SECRET_KEY = crypto.randomBytes(32).toString('hex'); // Секретный ключ для подписи токенов

// Пример данных пользователей
let users = [
    {
        id: uuidv4(),
        email: 'user1@example.com',
        password: 'password1',
        name: 'User 1',
        registrationDate: new Date(),
        lastLoginDate: null,
        status: 'active'
    },
    {
        id: uuidv4(),
        email: 'user2@example.com',
        password: 'password2',
        name: 'User 2',
        registrationDate: new Date(),
        lastLoginDate: null,
        status: 'active'
    },
    {
        id: uuidv4(),
        email: '1',
        password: '1',
        name: 'User 2',
        registrationDate: new Date(),
        lastLoginDate: null,
        status: 'active'
    }
];

app.use(cors());
app.use(bodyParser.json());

// Функция для создания JWT токена
const generateToken = (user) => {
    return jwt.sign({ id: user.id, email: user.email }, SECRET_KEY);
};

// Функция для проверки JWT токена
const verifyToken = (token) => {
    try {
        return jwt.verify(token, SECRET_KEY);
    } catch (error) {
        return null;
    }
};

// Получение всех пользователей
app.get('/users', (req, res) => {
    // Проверяем наличие токена в заголовках запроса
    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({ error: req.headers.authorization });

    }

    // Проверяем валидность токена
    const decodedToken = verifyToken(token);
    if (!decodedToken) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    // Получаем всех пользователей (в реальном приложении, здесь может быть логика для получения пользователей из базы данных)
    res.json(users);
});
app.get('/admin', (req, res) => {
    // В реальном приложении здесь может быть проверка на администраторские права
    res.json(users);
});
// Получение информации о текущем пользователе
app.get('/users/me', (req, res) => {
    const token = req.headers.authorization.split(' ')[1];

    if (!token || token.trim() === '') {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const decodedToken = verifyToken(token);
    if (!decodedToken) {
        return res.status(401).json({ error: 'Invalid token' });
    }

    const userId = decodedToken.id;
    const currentUser = users.find(user => user.id === userId);

    if (!currentUser) {
        return res.status(403).json({ error: 'User not found' });
    }


    res.json(currentUser);
});

// Добавление нового пользователя
app.post('/users', (req, res) => {
    const { email, password,name } = req.body;
    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
        return res.status(409).json({ error: 'User already exists' });
    }
    const newUser = {
        id: uuidv4(),
        email,
        password,
        name,
        registrationDate: new Date(),
        lastLoginDate: new Date(),
        status: 'active',
    };
    users.push(newUser);

    // Генерируем токен для нового пользователя
    const token = generateToken(newUser);

    // Отправляем токен вместе с сообщением об успешном создании пользователя
    res.status(201).json({ message: 'User created successfully', token });
});

// Эндпоинт для входа (логина) пользователя
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const user = users.find(user => user.email === email && user.password === password);
    if (user) {
        if (user.status === 'active') {
            // Генерируем токен для пользователя
            const token = generateToken(user);
            user.lastLoginDate = new Date();
            res.status(200).json({ message: 'Login successful', token });
        } else {
            res.status(403).json({ error: 'User account is inactive' });
        }
    } else {
        res.status(401).json({ error: 'Invalid email or password' });
    }
});
app.delete('/users/:id', (req, res) => {
    const userId = req.params.id.slice(1);
    const currentUser = getCurrentUser(req);
    if (currentUser.status === 'blocked'){
        return res.status(403).json({error: "Not permitted. User blocked"})
    }
    const index = users.findIndex(user => user.id === userId);
    if (index === -1) {
        return res.status(404).json({ error: 'User not found' });
    }

    users.splice(index, 1);

    res.json({ message: 'User deleted successfully' });
});
function getToken(req){
    const token = req.headers.authorization.split(' ')[1];

    if (!token || token.trim() === '') {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    return token


}

function getCurrentUser(req){
    const decodedToken = verifyToken(getToken(req));
    if (!decodedToken) {
        return res.status(401).json({ error: 'Invalid token' });
    }
    const userId = decodedToken.id;
    const currentUser = users.find(user => user.id === userId);

    if (!currentUser) {
        return res.status(403).json({ error: 'User not found' });
    }
    return currentUser
}
app.put('/admin/block', (req, res) => {
    const userIds = req.body.selectedRows;
    const currentUser = getCurrentUser(req);
    if (currentUser.status === 'blocked') {
        return res.status(403).json({ error: "Not permitted. User blocked" });
    }
    for (const userId of userIds) {
        const user = users.find(user => user.id === userId);
        if (user) {
            user.status = 'blocked';
        }
    }

    res.json({ message: 'Users blocked successfully'});
});

app.put('/users/unblock/:id', (req, res) => {
    const userId = req.params.id.slice(1);
    const currentUser = getCurrentUser(req);
    if (currentUser.status === 'blocked'){
        return res.status(403).json({error: "Not permitted. User blocked"})
    }
    const user = users.find(user => user.id === userId);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    user.status = 'active';

    res.json({ message: 'User unblocked successfully' });
});
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
console.log(app.get(`http://localhost:3000/users`))
