import express from 'express'

import { SingleEmailChecker } from '../controllers/email.controller.js';

const router = express.Router();

router.post("/verify-email", SingleEmailChecker)

export default router;