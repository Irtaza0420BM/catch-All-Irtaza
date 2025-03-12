import validator from 'validator';
import dns from 'dns/promises';
import { verifyEmail } from '@devmehq/email-validator-js';

// Input sanitization: work on a simple email string.
export const sanitizeEmail = (email) => {
  if (!email || typeof email !== 'string' || !email.trim()) {
    const error = new Error('Email failed to pass input validation test.');
    error.step = 'inputValidation';
    throw error;
  }
  if (email.includes(',') || email.includes(';') || email.trim().split(/\s+/).length > 1) {
    const error = new Error('Email failed to pass input validation test.');
    error.step = 'inputValidation';
    throw error;
  }
  return email.trim();
};

export const validateEmailFormat = (email) => {
  if (!validator.isEmail(email)) {
    const error = new Error('Email failed to pass syntax validation test.');
    error.step = 'syntaxValidation';
    throw error;
  }
};

export const validateDnsRecords = async (domain) => {
  try {
    const addresses = await dns.resolve(domain, 'A');
    if (!addresses.length) {
      const error = new Error('Email failed to pass dns record validation test.');
      error.step = 'dnsValidation';
      throw error;
    }
  } catch (err) {
    const error = new Error('Email failed to pass dns record validation test.');
    error.step = 'dnsValidation';
    throw error;
  }
};

export const validateMxRecords = async (domain) => {
  try {
    const mxRecords = await dns.resolveMx(domain);
    const validMx = mxRecords.filter(record => record.exchange && record.exchange.trim());
    if (!validMx.length) {
      const error = new Error('Email failed to pass mx record validation test.');
      error.step = 'mxValidation';
      throw error;
    }
  } catch (err) {
    const error = new Error('Email failed to pass mx record validation test.');
    error.step = 'mxValidation';
    throw error;
  }
};

export const validateSMTPConnection = async (email) => {
  const result = await verifyEmail({
    emailAddress: email,
    verifySmtp: true,
    timeout: 3000,
  });
  if (result.validSmtp !== true) {
    const error = new Error('Email failed to pass smtp validation test.');
    error.step = 'smtpValidation';
    throw error;
  }
  return result;
};

export const validateSpfRecord = async (domain) => {
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
};

// export const validateDkimRecord = async (domain, selector = 'default') => {
//     let selectorsToTry = [selector];
//     if (domain.toLowerCase() === 'gmail.com') {
//       selectorsToTry = [
//         "default",
//         "google",
//         "google20161025",
//         "google1234567",
//         "selector1",
//         "selector2",
//         "k1",
//         "k2",
//         "ctct1",
//         "ctct2",
//         "sm",
//         "s1",
//         "s2",
//         "sig1",
//         "litesrv",
//         "zendesk1",
//         "zendesk2",
//         "mail",
//         "email",
//         "dkim",
//         "topd"
//       ];
//     }
    
//     for (const sel of selectorsToTry) {
//       try {
//         const dkimDomain = `${sel}._domainkey.${domain}`;
//         const txtRecords = await dns.resolveTxt(dkimDomain);
//         const flatRecords = txtRecords.flat();
//         const dkimRecords = flatRecords.filter(record => record.startsWith('v=DKIM1'));
//         if (dkimRecords.length) {
//           return;
//         }
//       } catch (e) {
//         continue;
//       }
//     }
    
//     const error = new Error('Email failed to pass DKIM record validation test.');
//     error.step = 'dkimValidation';
//     throw error;
//   };
  

export const validateDmarcRecord = async (domain) => {
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
};

// Disposable Domain Check – use a local list of known disposable domains.
const disposableDomains = [
  "mailinator.com",
  "10minutemail.com",
  "tempmail.com",
  "guerrillamail.com",
  "discard.email",
  "yopmail.com"
];

export const checkDisposableDomain = (domain) => {
  if (disposableDomains.includes(domain.toLowerCase())) {
    const error = new Error('Email failed disposable domain validation test.');
    error.step = 'disposableDomainValidation';
    throw error;
  }
};

// DNSBL (Blacklist) Check – check MX IP addresses against DNSBL zones.
const dnsblZones = [
  "zen.spamhaus.org",
  "b.barracudacentral.org",
  "bl.spamcop.net",
  "dnsbl.sorbs.net",
  "spam.dnsbl.sorbs.net",
  "cbl.abuseat.org"
];

export const validateDnsblRecords = async (domain) => {
  try {
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
            // A successful resolution means the IP is blacklisted.
            await dns.resolve4(query);
            const error = new Error(`Email failed DNSBL validation: IP ${ip} is listed in ${zone}.`);
            error.step = 'dnsblValidation';
            throw error;
          } catch (err) {
            // ENOTFOUND means not listed; ignore other errors.
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
};
