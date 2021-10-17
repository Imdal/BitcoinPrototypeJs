import crypto from 'crypto';
import MerkleTree from "merkletreejs";
import cryptojs from 'crypto-js';


class User {
    constructor(name, credits) {
        this.name = name;
        this.credits = credits;
        const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa', {
            modulusLength: 1024,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
        this.private_key = privateKey.toString();
        this.public_key = publicKey.toString();


        console.log(this.name," public key is: ", this.public_key);
        console.log(this.name," private key is: ", this.private_key);
        console.log();
    }

    static getUser(public_key, user_list) {
        let selected_user;
        user_list.forEach(user => user.public_key===public_key ? selected_user = user : null)
        return selected_user;
    }

    removeCoin(amount) {
        this.credits = this.credits-amount;
    }

    addCoin(amount) {
        this.credits = this.credits+amount;
    }

    verify(signature, transaction) {
        if(this.credits<transaction.amount)
            return false;
        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(JSON.stringify(transaction))
        return verifier.verify(this.public_key, signature, 'hex');
    }

    sign(transaction) {
        const sign = crypto.createSign('RSA-SHA256');
        sign.update(JSON.stringify(transaction))
        return sign.sign(this.private_key, 'hex');
    }
}

class Transaction {
    constructor(sender, receiver, amount) {
        this.sender = sender;
        this.receiver = receiver;
        this.amount = amount;
    }

    setUserCredits() {
        User.getUser(this.sender,user_list).removeCoin(this.amount);
        User.getUser(this.receiver,user_list).addCoin(this.amount);
    }

}

class BlockChain {

    blockChain = [];

    constructor() {
        let hash = 0;
        let timestamp = Date.now();
        let nonce = this.generateNonceHashAndCheck(timestamp, hash);

        this.blockChain.push({
            previous: '',
            nonce: nonce,
            hash: hash,
            timestamp: timestamp
        })
    }

    generateNonceHashAndCheck(timestamp,hash) {
        console.log("_____ Generate nonce _____")
        while(true) {
            let nonce = this.generateNonce();
            if(this.checkHash(this.generateHashOfBlock(hash, timestamp, nonce)))
                return nonce;
        }
    }

    generateNonce() {
        return crypto.randomBytes( 4 ).toString('hex');
    }

    generateHashOfBlock(hash, timestamp, nonce) {
        return cryptojs.SHA256(JSON.stringify({hash: hash, timestamp: timestamp,nonce: nonce})).toString();
    }

    checkHash(hash) {
        var result = true;
        for (let i = 0; i < 4; i++) {
            if (hash[i] !== '0') {
                result = false;
            }
        }
        return result;
    }

    addBlock(hash) {
        let timestamp = Date.now();
        let nonce = this.generateNonceHashAndCheck(timestamp, hash);
        let previous = this.getLastBlock();
        this.blockChain.push({
            previous: this.generateHashOfBlock(previous['hash'],previous['timestamp'],previous['nonce']),
            nonce: nonce,
            hash: hash,
            timestamp: timestamp
        })
    }

    getLastBlock() {
        return this.blockChain[this.blockChain.length-1];
    }
}


console.log("_____ Generate users _____");

let user_list = [];
const user1 = new User('user1', 50);
const user2 = new User('user2', 100);
const user3 = new User('user3', 150);
const user4 = new User('user4', 200);

user_list.push(user1);
user_list.push(user2);
user_list.push(user3);
user_list.push(user4);

console.log("_____ Create transactions _____");

const transaction1 = new Transaction(user1.public_key, user2.public_key, 50);
const transaction2 = new Transaction(user2.public_key, user3.public_key, 100);
const transaction3 = new Transaction(user3.public_key, user4.public_key, 150);
const transaction4 = new Transaction(user4.public_key, user1.public_key, 200);

console.log("_____ Create signatures _____");

const sign1 = user1.sign(transaction1);
const sign2 = user2.sign(transaction2);
const sign3 = user3.sign(transaction3);
const sign4 = user4.sign(transaction4);

console.log("_____ Verify signatures _____");
console.log(user_list);
const verify1 = user1.verify(sign1, transaction1);
const verify2 = user2.verify(sign2, transaction2);
const verify3 = user3.verify(sign3, transaction3);
const verify4 = user4.verify(sign4, transaction4);

let leaves = [];
if(verify1) {
    transaction1.setUserCredits()
    leaves.push(sign1);
}
if(verify2) {
    transaction2.setUserCredits()
    leaves.push(sign2);
}
if(verify3) {
    transaction3.setUserCredits()
    leaves.push(sign3);
}
if(verify4) {
    transaction4.setUserCredits()
    leaves.push(sign4);
}
console.log(user_list);
console.log("_____ Create Merkle tree _____")

leaves.map(x => cryptojs.SHA256(x));
const tree = new MerkleTree.MerkleTree(leaves, cryptojs.SHA256);
const root = tree.getRoot().toString('hex');

// const leaf = cryptojs.SHA256(sign1);
// const proof = tree.getProof(leaf);
// console.log(tree.verify(proof, leaf, root)); // true
// console.log(root);



console.log("_____ Add first element of block chain _____")
let blockChain = new BlockChain()

console.log("_____ Add next element of block chain _____")
blockChain.addBlock(root);
console.log(blockChain);
console.log(blockChain.blockChain.length);

