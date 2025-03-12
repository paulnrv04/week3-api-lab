const express = require('express');
const app = express();
const PORT = 4000;

app.use(express.json());

// Sample Products Data
const products = [
    { id: 1, name: 'Laptop' },
    { id: 2, name: 'Smartphone' }
];

// Public Endpoint
app.get('/api/products', (req, res) => {
    res.json(products);
});

// Start Server
app.listen(PORT, () => {
    console.log(`Product Service running on port ${PORT}`);
});