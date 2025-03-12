import express from 'express';
import dotenv from 'dotenv';

import router from './routes/email.routes.js';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

app.use("/api", router);

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});