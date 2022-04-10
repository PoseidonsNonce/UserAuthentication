const argon2 = require('argon2');
const crypto = require('crypto')
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
        
        /* get hash of password */
        hash = await sha256Digest(password, 'hex');
        
        /* Get Hash of Username */
        const userhash = sha256Digest(username, 'hex');

        /*If hash does not exists, then username does not exist */
        if(!fs.existsSync('./users/' + userhash + '.json')){
            console.log("Username does not exist. ");
            return ;
        }

        /** Load user file if the user exists */
        let userfile = fs.readFileSync('./users/' + userhash + '.json');
        let user = JSON.parse(userfile);

        /** Check if password hash matches users saved password hash  */
        if(hash != user.hash){
            console.log("Wrong Password");
            return ;
        }

        /** Notify / greeting  */
        console.log("Logged In")    

        /* Derive the Wrapping key give then provided password and saved user salt */
        const s = Buffer.from(user.salt, 'base64');
        const l = 32;
        wk = await deriveKey(password, s, l);

        /** Unwrap the user key using AES-KW (AES-256 in "wrap" mode), using the wrapping key
        Note that the IV is always 0xA6A6A6A6A6A6A6A6 as defined by RFC3394 */
        const iv = Buffer.from('A6A6A6A6A6A6A6A6', 'hex')
        const decipher = crypto.createDecipheriv('id-aes256-wrap', wk, iv)
        /* Load wraped user key from user file */
        const wuk = Buffer.from(user.wuk, 'base64')
        const uk = Buffer.concat([
            decipher.update(wuk),
            decipher.final()
        ])

        /* User the UK to encrypt / decrypt */
        console.log("UK Retreived and ready to use") 
    })

}

main()