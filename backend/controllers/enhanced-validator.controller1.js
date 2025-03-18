
const validator = require('validator');
const dns = require('dns/promises');
const { verifyEmail } = require('@devmehq/email-validator-js');
const tf = require('@tensorflow/tfjs-node');
const disposableDomains = require('disposable-email-domains');

class EmailValidator {
  constructor() {
    this.model = null;
    this.featureLabels = [
      'inputValidation',
      'syntaxValidation',
      'disposableDomain',
      'dnsValidation',
      'mxValidation',
      'dnsblValidation',
      'spfValidation',
      'dmarcValidation',
      'smtpValidation'
    ];
  }

  async sanitizeEmail(email) {
    try {
      if (!email || typeof email !== 'string' || !email.trim()) return false;
      if (email.includes(',') || email.includes(';') || email.trim().split(/\s+/).length > 1) return false;
      return email.trim();
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
          return;
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
                await dns.resolve4(query);
                const error = new Error(`Email failed DNSBL validation: IP ${ip} is listed in ${zone}.`);
                error.step = 'dnsblValidation';
                throw error;
              } catch (err) {
                if (err.code !== 'ENOTFOUND') {
                  continue;
                }
              }
            }
          }
        }
      } catch (err) {
        if (err.step === 'dnsblValidation') {
          throw err;
        }
      }
  }

  async validateSpfRecord(domain) {
    try {
    const txtRecords = await dns.resolveTxt(domain);
    const flatRecords = txtRecords.flat();
    const spfRecords = flatRecords.filter(record => record.startsWith('v=spf1'));
    if (!spfRecords.length) {
      const error = new Error('Email failed to pass SPF record validation test.');
      error.step = 'spfValidation';
      throw error;
    }
  } catch (err) {
    const error = new Error('Email failed to pass SPF record validation test.');
    error.step = 'spfValidation';
    throw error;
  }
  }

  async validateDmarcRecord(domain) {
    try {
    const dmarcDomain = `_dmarc.${domain}`;
    const txtRecords = await dns.resolveTxt(dmarcDomain);
    const flatRecords = txtRecords.flat();
    const dmarcRecords = flatRecords.filter(record => record.startsWith('v=DMARC1'));
    if (!dmarcRecords.length) {
      const error = new Error('Email failed to pass DMARC record validation test.');
      error.step = 'dmarcValidation';
      throw error;
    }
  } catch (err) {
    const error = new Error('Email failed to pass DMARC record validation test.');
    error.step = 'dmarcValidation';
    throw error;
  }
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

  async extractFeatures(email) {
    const features = {};
    
    try {
      const sanitized = await this.sanitizeEmail(email);
      features.inputValidation = !!sanitized;
      
      features.syntaxValidation = await this.validateEmailFormat(sanitized);
      
      const [localPart, domain] = sanitized.split('@');
      features.disposableDomain = await this.checkDisposableDomain(domain);
      features.dnsValidation = await this.validateDnsRecords(domain);
      features.mxValidation = await this.validateMxRecords(domain);
      features.dnsblValidation = await this.validateDnsblRecords(domain);
      features.spfValidation = await this.validateSpfRecord(domain);
      features.dmarcValidation = await this.validateDmarcRecord(domain);
      features.smtpValidation = await this.validateSMTPConnection(sanitized);
      
      return Object.values(features).map(v => v ? 1 : 0);
    } catch (error) {
      return Array(this.featureLabels.length).fill(0);
    }
  }

  createModel() {
    const model = tf.sequential({
      layers: [
        tf.layers.simpleRNN({
          units: 64,
          activation: 'relu',
          returnSequences: false,
          inputShape: [this.featureLabels.length, 1]
        }),
        tf.layers.dense({units: 32, activation: 'relu'}),
        tf.layers.dense({units: 1, activation: 'sigmoid'})
      ]
    });

    model.compile({
      optimizer: 'adam',
      loss: 'binaryCrossentropy',
      metrics: ['accuracy']
    });

    return model;
  }

  async trainModel(dataset) {
    this.model = this.createModel();
    
    const features = dataset.map(entry => entry.features);
    const labels = dataset.map(entry => entry.label);

    const xs = tf.tensor3d(features, [features.length, this.featureLabels.length, 1]);
    const ys = tf.tensor2d(labels, [labels.length, 1]);

    await this.model.fit(xs, ys, {
      epochs: 50,
      batchSize: 32,
      validationSplit: 0.2,
      callbacks: tf.node.tensorBoard('/tmp/logs')
    });
  }

  async predict(email) {
    const features = await this.extractFeatures(email);
    const tensor = tf.tensor3d([features], [1, this.featureLabels.length, 1]);
    const prediction = this.model.predict(tensor);
    return prediction.dataSync()[0];
  }

  async saveModel(path = 'file://./model') {
    await this.model.save(path);
  }

  async loadModel(path = 'file://./model') {
    this.model = await tf.loadLayersModel(`${path}/model.json`);
  }
}

module.exports = new EmailValidator();

