const express = require('express');
const bodyParser = require('body-parser');
const validator = require('./controllers/enhanced-validator.controller');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const app = express();

app.use(morgan('combined')); 
app.use(bodyParser.json({ limit: '10kb' })); 

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100, 
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.post('/train', async (req, res) => {
  try {
    const { dataset } = req.body;

    if (!Array.isArray(dataset)) {
      return res.status(400).json({ error: 'Dataset must be an array' });
    }

    await validator.trainModel(dataset);
    await validator.saveModel();

    res.status(200).json({ 
      success: true,
      message: `Model trained successfully with ${dataset.length} samples`
    });
  } catch (error) {
    console.error('Training error:', error);
    res.status(500).json({ 
      error: 'Model training failed',
      details: error.message 
    });
  }
});

app.post('/validate', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: 'Email parameter is required and must be a string' });
    }

    if (!validator.model) {
      return res.status(503).json({ 
        error: 'Model not initialized. Please train the model first.' 
      });
    }

    const features = await validator.extractFeatures(email);
    const validationResult = features.every(v => v === 1);
    const aiScore = await validator.predict(email);

    const result = {
      email,
      traditionalValidation: validationResult,
      aiValidation: aiScore >= 0.5,
      aiConfidence: Number(aiScore.toFixed(4)), 
      features: validator.featureLabels.reduce((acc, label, index) => {
        acc[label] = features[index] === 1;
        return acc;
      }, {})
    };

    res.status(200).json(result);
  } catch (error) {
    console.error('Validation error:', error);
    res.status(500).json({ 
      error: 'Email validation failed',
      details: error.message 
    });
  }
});

app.post('/evaluate', async (req, res) => {
  try {
    const { testData } = req.body;

    if (!Array.isArray(testData)) {
      return res.status(400).json({ error: 'Test data must be an array' });
    }

    const evaluation = await validator.evaluateModel(testData);

    res.status(200).json(evaluation);
  } catch (error) {
    console.error('Evaluation error:', error);
    res.status(500).json({ 
      error: 'Model evaluation failed',
      details: error.message 
    });
  }
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    details: err.message 
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
});