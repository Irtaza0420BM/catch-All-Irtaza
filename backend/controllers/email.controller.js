import {
    sanitizeEmail,
    validateEmailFormat,
    validateDnsRecords,
    validateMxRecords,
    validateSMTPConnection,
    validateSpfRecord,
    validateDkimRecord,
    validateDmarcRecord,
    checkDisposableDomain,
    validateDnsblRecords
  } from './validator.controller.js';
  
  export const checkEmailValidation = async (email) => {
    let domain, localPart;
  
    try {
      email = sanitizeEmail(email);
    } catch (err) {
      return { email, status: false, verification: 'inputValidation', error: err.message };
    }
  
    try {
      validateEmailFormat(email);
    } catch (err) {
      return { email, status: false, verification: 'syntaxValidation', error: err.message };
    }
  
    try {
      [localPart, domain] = email.split('@');
    } catch (err) {
      return { email, status: false, verification: 'domainExtraction', error: 'Email failed to pass domain extraction test.' };
    }
  
    try {
      checkDisposableDomain(domain);
    } catch (err) {
      return { email, status: false, verification: 'disposableDomainValidation', error: err.message };
    }
  
    try {
      await validateDnsRecords(domain);
    } catch (err) {
      return { email, status: false, verification: 'dnsValidation', error: err.message };
    }
  
    try {
      await validateMxRecords(domain);
    } catch (err) {
      return { email, status: false, verification: 'mxValidation', error: err.message };
    }
  
    try {
      await validateDnsblRecords(domain);
    } catch (err) {
      return { email, status: false, verification: 'dnsblValidation', error: err.message };
    }
  
    try {
      await validateSpfRecord(domain);
    } catch (err) {
      return { email, status: false, verification: 'spfValidation', error: err.message };
    }
  
    // DKIM validation is currently commented out.
    /*
    try {
      await validateDkimRecord(domain, 'default');
    } catch (err) {
      return { email, status: false, verification: 'dkimValidation', error: err.message };
    }
    */
  
    try {
      await validateDmarcRecord(domain);
    } catch (err) {
      return { email, status: false, verification: 'dmarcValidation', error: err.message };
    }
  
    try {
      await validateSMTPConnection(email);
    } catch (err) {
      return { email, status: false, verification: 'smtpValidation', error: err.message };
    }
  
    return {
      email,
      status: true,
      message: 'Email validation passed.',
      checkedAt: new Date().toISOString(),
      verification: 'all'
    };
  };
  