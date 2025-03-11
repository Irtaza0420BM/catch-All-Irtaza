import fs from 'fs';
import csv from 'csv-parser';
import { checkEmailValidation } from './controllers/email.controller.js';

const emails = [];
const outputFile = 'results.csv';

fs.writeFileSync(outputFile, 'Email,MethodUsed,Status\n');

fs.createReadStream('./email.csv')
  .pipe(csv())
  .on('data', (row) => {
    if (row.email) {
      emails.push(row.email);
    }
  })
  .on('end', async () => {
    console.log(`CSV file processed. Found ${emails.length} emails.`);

    const BATCH_SIZE = 10;
    
    for (let i = 0; i < emails.length; i += BATCH_SIZE) {
      const batch = emails.slice(i, i + BATCH_SIZE);

      await Promise.all(batch.map(async (email) => {
        try {
          const result = await checkEmailValidation(email);
          const resultRow = `${email},${result.verification},${result.status}\n`;
          fs.appendFileSync(outputFile, resultRow);
          console.log(result);
        } catch (error) {
          const methodUsed = error.step || 'unknown';
          const resultRow = `${email},${methodUsed},failed\n`;
          fs.appendFileSync(outputFile, resultRow);
          console.error(`Error processing ${email}: ${error.message}`);
        }
      }));
    }

    console.log('All emails have been processed.');
  });
