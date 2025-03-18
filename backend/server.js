
const express = require('express');
const bodyParser = require('body-parser');
const validator = require('./controllers/enhanced-validator.controller');
const app = express();

app.use(bodyParser.json());

app.post('/train', async (req, res) => {
  try {
    const { dataset } = req.body;
    await validator.trainModel(dataset);
    await validator.saveModel();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/validate', async (req, res) => {
  try {
    const { email } = req.body;
    
    const features = await validator.extractFeatures(email);
    const validationResult = features.every(v => v === 1);
    
    const aiScore = await validator.predict(email);
    
    const result = {
      email,
      traditionalValidation: validationResult,
      aiValidation: aiScore >= 0.5,
      aiConfidence: aiScore,
      features: validator.featureLabels.reduce((acc, label, index) => {
        acc[label] = features[index] === 1;
        return acc;
      }, {})
    };

    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});