const argon2 = require('argon2');
const crypto = require('crypto')
const randomBytes = require('util').promisify(crypto.randomBytes);
const fs = require('fs')



async function deriveKey(passphrase, salt, length) {

    try{
        const params = { 
            raw: true,
            hashLength: length,
            salt: salt,
            type: argon2.argon2id,
            timeCost: 3, 
            memoryCost: 4096, 
            parallelism: 1,
            version: 0x13,
        } 
        const result = await argon2.hash(passphrase, params);
        return result;
    }
    catch(err){
        console.error('An internal error occurred: ', err)
    }

}

function sha256Digest(message, encoding){
    return crypto.createHash('sha256').update(message).digest(encoding);
}


/* AES 256 GCM */

const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
  });

async function main(){

    var username; 
    var wk;
    var hash; 
    var password; 

    readline.question('What is your Username: ', u => {
        readline.question('What is your Password: ', x => {
            username = u;
            password = x;
            readline.close();
        })
    });

    readline.on("close", async () => {
        /* Hash of Username */
        const userhash = sha256Digest(username, 'hex');
                
        /* If hash exists, then username is already taken */
        if(fs.existsSync(userhash + '.json')){
            console.log("Username already exists, try another");
            return ;
        }
        /* KDF - derive wrapping key */
        const s = await randomBytes(16);
        const l = 32;
        wk = await deriveKey(password, s, l);

        /* Password Hash */
        hash = await sha256Digest(password, 'hex');
        
        /* Create User Key */
        const uk = await randomBytes(32);

        /*  Wrap the user key with the wrapping key, using AES-KW (AES-256 in "wrap" mode)
            Note that the IV is always 0xA6A6A6A6A6A6A6A6 as defined by RFC3394 
            */    
        const iv = Buffer.from('A6A6A6A6A6A6A6A6', 'hex')
        const cipher = crypto.createCipheriv('id-aes256-wrap', wk, iv)
        const wuk = Buffer.concat([
            cipher.update(uk),
            cipher.final()
        ])

        /* Greeting */
        console.log(`Hey there ${username}!`);

        /* Create new user object */
        const newUser = {
            "wuk": wuk.toString('base64'),
            "hash": hash,
            "salt": s.toString('base64'),
        }

        /* Stringify and save */
        const data = JSON.stringify(newUser);
        fs.writeFileSync( './users/' + userhash + '.json', data);
    })

}

main()