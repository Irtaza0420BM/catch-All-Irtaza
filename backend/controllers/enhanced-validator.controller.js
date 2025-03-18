const validator = require('validator');
const dns = require('dns/promises');
const { verifyEmail } = require('@devmehq/email-validator-js');
const tf = require('@tensorflow/tfjs-node');
const disposableDomains = require('disposable-email-domains');
const levenshtein = require('fast-levenshtein');

class EmailValidator {
  constructor() {
    this.model = null;
    this.commonDomains = [
      'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
      'icloud.com', 'protonmail.com', 'mail.com', 'zoho.com', 'yandex.com'
    ];
    this.topLevelDomains = [
      'com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'us', 'uk',
      'ca', 'au', 'de', 'fr', 'jp', 'cn', 'ru', 'in', 'br', 'it'
    ];
    this.featureLabels = [
      'inputValidation',
      'syntaxValidation',
      'emailLength',
      'localPartLength',
      'domainLength',
      'disposableDomain',
      'commonDomain',
      'domainTypoScore',
      'tldPopularity',
      'dnsValidation',
      'mxValidation',
      'mxRecordCount',
      'dnsblValidation',
      'spfValidation',
      'dmarcValidation',
      'dkimValidation',
      'smtpValidation',
      'hasNumbers',
      'specialCharCount',
      'consecutiveSpecialChars'
    ];
  }

  async sanitizeEmail(email) {
    try {
      if (!email || typeof email !== 'string' || !email.trim()) return false;
      if (email.includes(',') || email.includes(';') || email.trim().split(/\s+/).length > 1) return false;
      return email.trim().toLowerCase();
    } catch {
      return false;
    }
  }

  async validateEmailFormat(email) {
    return validator.isEmail(email);
  }

  async checkDisposableDomain(domain) {
    return !disposableDomains.includes(domain.toLowerCase());
  }

  isCommonDomain(domain) {
    return this.commonDomains.includes(domain.toLowerCase());
  }

  calculateDomainTypoScore(domain) {
    if (this.isCommonDomain(domain)) return 0;
    
    const minDistance = Math.min(
      ...this.commonDomains.map(commonDomain => 
        levenshtein.get(domain.toLowerCase(), commonDomain)
      )
    );
    
    const normalizedScore = Math.min(minDistance / 3, 1);
    return normalizedScore;
  }

  tldPopularityScore(domain) {
    const tld = domain.split('.').pop().toLowerCase();
    return this.topLevelDomains.includes(tld) ? 1 : 0.5;
  }

  async validateDnsRecords(domain) {
    try {
      const addresses = await dns.resolve(domain, 'A');
      return addresses.length > 0;
    } catch {
      return false;
    }
  }

  async validateMxRecords(domain) {
    try {
      const mxRecords = await dns.resolveMx(domain);
      return mxRecords.some(record => record.exchange && record.exchange.trim());
    } catch {
      return false;
    }
  }

  async getMxRecordCount(domain) {
    try {
      const mxRecords = await dns.resolveMx(domain);
      return Math.min(mxRecords.length / 5, 1); // Normalize, capping at 5 records
    } catch {
      return 0;
    }
  }

  async validateDnsblRecords(domain) {
    try {
      const dnsblZones = [
        "zen.spamhaus.org",
        "b.barracudacentral.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "spam.dnsbl.sorbs.net",
        "cbl.abuseat.org"
      ];
      const mxRecords = await dns.resolveMx(domain);
      if (!mxRecords.length) {
        return true; 
      }
      
      for (const mx of mxRecords) {
        let ipAddresses;
        try {
          ipAddresses = await dns.resolve4(mx.exchange);
        } catch (e) {
          continue;
        }
        
        for (const ip of ipAddresses) {
          const reversedIP = ip.split('.').reverse().join('.');
          for (const zone of dnsblZones) {
            const query = `${reversedIP}.${zone}`;
            try {
              const result = await dns.resolve4(query);
              if (result && result.length > 0) {
                return false; 
              }
            } catch (err) {
              if (err.code !== 'ENOTFOUND') {
                continue;
              }
            }
          }
        }
      }
      return true; 
    } catch (err) {
      return false;
    }
  }
 
  async validateSpfRecord(domain) {
    try {
      const txtRecords = await dns.resolveTxt(domain);
      const flatRecords = txtRecords.flat();
      return flatRecords.some(record => record.startsWith('v=spf1'));
    } catch {
      return false;
    }
  }

  async validateDmarcRecord(domain) {
    try {
      const dmarcDomain = `_dmarc.${domain}`;
      const txtRecords = await dns.resolveTxt(dmarcDomain);
      const flatRecords = txtRecords.flat();
      return flatRecords.some(record => record.startsWith('v=DMARC1'));
    } catch {
      return false;
    }
  }

  async validateDkimRecord(domain) {
    const selectors = ['default', 'google', 'k1', 'selector1', 'selector2', 'dkim'];
    
    for (const selector of selectors) {
      try {
        const dkimDomain = `${selector}._domainkey.${domain}`;
        const txtRecords = await dns.resolveTxt(dkimDomain);
        const flatRecords = txtRecords.flat();
        if (flatRecords.some(record => record.startsWith('v=DKIM1'))) {
          return true;
        }
      } catch {
        continue;
      }
    }
    
    return false;
  }

  async validateSMTPConnection(email) {
    try {
      const result = await verifyEmail({
        emailAddress: email,
        verifySmtp: true,
        timeout: 3000,
      });
      return result.validSmtp === true;
    } catch {
      return false;
    }
  }

  hasNumbers(str) {
    return /\d/.test(str);
  }

  countSpecialChars(str) {
    return (str.match(/[^\w\s@]/g) || []).length;
  }

  hasConsecutiveSpecialChars(str) {
    return /[^\w\s@]{2,}/.test(str);
  }

  async extractFeatures(email) {
    const features = {};
    
    try {
      const sanitized = await this.sanitizeEmail(email);
      features.inputValidation = sanitized ? 1 : 0;
      
      if (!sanitized) {
        return Array(this.featureLabels.length).fill(0);
      }
      
      features.syntaxValidation = await this.validateEmailFormat(sanitized) ? 1 : 0;
      
      const [localPart, domain] = sanitized.split('@');
      
      features.emailLength = Math.min(sanitized.length / 50, 1); 
      features.localPartLength = Math.min(localPart.length / 30, 1); 
      features.domainLength = Math.min(domain.length / 30, 1); 
      
      features.disposableDomain = await this.checkDisposableDomain(domain) ? 1 : 0;
      features.commonDomain = this.isCommonDomain(domain) ? 1 : 0;
      features.domainTypoScore = this.calculateDomainTypoScore(domain);
      features.tldPopularity = this.tldPopularityScore(domain);
      
      features.dnsValidation = await this.validateDnsRecords(domain) ? 1 : 0;
      features.mxValidation = await this.validateMxRecords(domain) ? 1 : 0;
      features.mxRecordCount = await this.getMxRecordCount(domain);
      features.dnsblValidation = await this.validateDnsblRecords(domain) ? 1 : 0;
      
      features.spfValidation = await this.validateSpfRecord(domain) ? 1 : 0;
      features.dmarcValidation = await this.validateDmarcRecord(domain) ? 1 : 0;
      features.dkimValidation = await this.validateDkimRecord(domain) ? 1 : 0;
      
      features.smtpValidation = await this.validateSMTPConnection(sanitized) ? 1 : 0;
      
      features.hasNumbers = this.hasNumbers(localPart) ? 1 : 0;
      features.specialCharCount = Math.min(this.countSpecialChars(localPart) / 5, 1);
      features.consecutiveSpecialChars = this.hasConsecutiveSpecialChars(localPart) ? 1 : 0;
      
      for (const feature of this.featureLabels) {
        if (features[feature] === undefined) {
          features[feature] = 0;
        }
      }
      
      return this.featureLabels.map(label => features[label]);
    } catch (error) {
      console.error('Error extracting features:', error);
      return Array(this.featureLabels.length).fill(0);
    }
  }

  createModel() {
    const model = tf.sequential();
    
    model.add(tf.layers.bidirectional({
      layer: tf.layers.lstm({
        units: 64,
        returnSequences: true
      }),
      inputShape: [this.featureLabels.length, 1]
    }));
    
    model.add(tf.layers.lstm({
      units: 32,
      returnSequences: false
    }));
    
    model.add(tf.layers.dropout({rate: 0.3}));
    
    model.add(tf.layers.dense({units: 32, activation: 'relu'}));
    model.add(tf.layers.batchNormalization());
    
    model.add(tf.layers.dense({units: 1, activation: 'sigmoid'}));

    const optimizer = tf.train.rmsprop(0.001);
    
    model.compile({
      optimizer: optimizer,
      loss: 'binaryCrossentropy',
      metrics: ['accuracy', 'precision', 'recall']
    });

    return model;
  }

  async trainModel(dataset, validationData = null) {
    this.model = this.createModel();
    
    const features = dataset.map(entry => entry.features);
    const labels = dataset.map(entry => entry.label);

    const xs = tf.tensor3d(features, [features.length, this.featureLabels.length, 1]);
    const ys = tf.tensor2d(labels, [labels.length, 1]);
    
    const validationDataset = validationData ? {
      xs: tf.tensor3d(
        validationData.map(entry => entry.features), 
        [validationData.length, this.featureLabels.length, 1]
      ),
      ys: tf.tensor2d(
        validationData.map(entry => entry.label),
        [validationData.length, 1]
      )
    } : null;

    await this.model.fit(xs, ys, {
      epochs: 100,
      batchSize: 32,
      validationData: validationDataset || undefined,
      validationSplit: validationData ? 0 : 0.2,
      callbacks: [
        tf.callbacks.earlyStopping({
          monitor: 'val_accuracy',
          patience: 10,
          minDelta: 0.01,
          mode: 'max'
        }),
        {
          onEpochEnd: (epoch, logs) => {
            if (epoch > 0 && epoch % 20 === 0) {
              const newLR = this.model.optimizer.learningRate * 0.8;
              this.model.optimizer.learningRate = newLR;
              console.log(`Epoch ${epoch}: reducing learning rate to ${newLR}`);
            }
            console.log(`Epoch ${epoch}: accuracy = ${logs.acc}, val_accuracy = ${logs.val_acc}`);
          }
        },
        tf.node.tensorBoard('/tmp/email_validator_logs')
      ]
    });
    
    this.calculateFeatureImportance();
    
    return this.model;
  }
  
  calculateFeatureImportance() {
    // This is a simplified approach to estimate feature importance
    const baselineEmail = 'test@example.com';
    
    this.extractFeatures(baselineEmail).then(baseFeatures => {
      console.log('Feature importance (estimated):');
      
      const baseline = tf.tensor3d([baseFeatures], [1, this.featureLabels.length, 1]);
      const baselinePrediction = this.model.predict(baseline).dataSync()[0];
      
      for (let i = 0; i < this.featureLabels.length; i++) {
        const modifiedFeatures = [...baseFeatures];
        modifiedFeatures[i] = baseFeatures[i] === 1 ? 0 : 1;
        
        const modified = tf.tensor3d([modifiedFeatures], [1, this.featureLabels.length, 1]);
        const modifiedPrediction = this.model.predict(modified).dataSync()[0];
        
        const impact = Math.abs(modifiedPrediction - baselinePrediction);
        console.log(`${this.featureLabels[i]}: ${impact.toFixed(4)}`);
      }
    });
  }

  async predict(email) {
    try {
      const features = await this.extractFeatures(email);
      const tensor = tf.tensor3d([features], [1, this.featureLabels.length, 1]);
      const prediction = this.model.predict(tensor);
      const confidence = prediction.dataSync()[0];
      
      return {
        valid: confidence >= 0.5,
        confidence,
        features: Object.fromEntries(this.featureLabels.map((label, i) => [label, features[i]]))
      };
    } catch (error) {
      console.error('Prediction error:', error);
      return { valid: false, confidence: 0, error: error.message };
    }
  }

  async evaluateModel(testData) {
    const predictions = [];
    const actuals = [];
    const results = [];
    
    for (const sample of testData) {
      const prediction = await this.predict(sample.email);
      predictions.push(prediction.valid ? 1 : 0);
      actuals.push(sample.label);
      
      results.push({
        email: sample.email,
        actual: sample.label === 1 ? 'valid' : 'invalid',
        predicted: prediction.valid ? 'valid' : 'invalid',
        confidence: prediction.confidence,
        correct: (prediction.valid ? 1 : 0) === sample.label
      });
    }
    
    let truePositives = 0;
    let falsePositives = 0;
    let trueNegatives = 0;
    let falseNegatives = 0;
    
    for (let i = 0; i < predictions.length; i++) {
      if (predictions[i] === 1 && actuals[i] === 1) truePositives++;
      if (predictions[i] === 1 && actuals[i] === 0) falsePositives++;
      if (predictions[i] === 0 && actuals[i] === 0) trueNegatives++;
      if (predictions[i] === 0 && actuals[i] === 1) falseNegatives++;
    }
    
    const accuracy = (truePositives + trueNegatives) / predictions.length;
    const precision = truePositives / (truePositives + falsePositives) || 0;
    const recall = truePositives / (truePositives + falseNegatives) || 0;
    const f1Score = 2 * (precision * recall) / (precision + recall) || 0;
    
    return {
      metrics: {
        accuracy,
        precision,
        recall,
        f1Score,
        truePositives,
        falsePositives,
        trueNegatives,
        falseNegatives
      },
      results
    };
  }

  async saveModel(path = 'file://./email_validator_model') {
    await this.model.save(path);
    console.log(`Model saved to ${path}`);
  }

  async loadModel(path = 'file://./email_validator_model') {
    this.model = await tf.loadLayersModel(`${path}/model.json`);
    console.log(`Model loaded from ${path}`);
    return this.model;
  }
  
  async crossValidate(dataset, k = 5) {
    const shuffled = [...dataset].sort(() => 0.5 - Math.random());
    
    const folds = Array(k).fill().map((_, i) => {
      const start = Math.floor(i * shuffled.length / k);
      const end = Math.floor((i + 1) * shuffled.length / k);
      return shuffled.slice(start, end);
    });
    
    const results = [];
    
    for (let i = 0; i < k; i++) {
      console.log(`Fold ${i+1}/${k}`);
      
      const validationSet = folds[i];
      
      const trainingSet = folds.filter((_, j) => j !== i).flat();
      
      this.model = this.createModel();
      await this.trainModel(trainingSet);
      
      const validationEmails = validationSet.map(item => ({
        email: item.email,
        label: item.label
      }));
      
      const evalResult = await this.evaluateModel(validationEmails);
      results.push(evalResult.metrics);
      
      console.log(`Fold ${i+1} accuracy: ${evalResult.metrics.accuracy.toFixed(4)}`);
    }
    
    const avgAccuracy = results.reduce((sum, r) => sum + r.accuracy, 0) / k;
    const avgPrecision = results.reduce((sum, r) => sum + r.precision, 0) / k;
    const avgRecall = results.reduce((sum, r) => sum + r.recall, 0) / k;
    const avgF1 = results.reduce((sum, r) => sum + r.f1Score, 0) / k;
    
    return {
      avgAccuracy,
      avgPrecision,
      avgRecall,
      avgF1,
      foldResults: results
    };
  }
}

function prepareData(emails, labels) {
  const validator = new EmailValidator();
  
  return Promise.all(emails.map(async (email, i) => {
    const features = await validator.extractFeatures(email);
    return {
      email,
      features,
      label: labels[i]
    };
  }));
}

async function demo() {
  const validator = new EmailValidator();
  
  const emails = [
    'john.doe@example.com',
    'jane.smith@gmail.com',
    'support@microsoft.com',
    'test@nonexistentdomain123456.com',
    'invalid@email',
  ];
  
  const labels = [1, 1, 1, 0, 0];
  
  const dataset = await prepareData(emails, labels);
  
  await validator.trainModel(dataset);
  
  for (const email of emails) {
    const result = await validator.predict(email);
    console.log(`${email}: ${result.valid ? 'Valid' : 'Invalid'} (${result.confidence.toFixed(4)})`);
  }
  
  const evaluation = await validator.evaluateModel(dataset);
  console.log('Evaluation:', evaluation.metrics);
  
  await validator.saveModel();
}

module.exports = EmailValidator;