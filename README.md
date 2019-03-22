[![CircleCI Status](https://circleci.com/gh/nknorg/nkn-client-js.svg?style=shield&circle-token=:circle-token)](https://circleci.com/gh/nknorg/nkn-client-js)

# nkn-client-js

[English](/README.md) •
[Русский](/docs/README-ru.md)

JavaScript implementation of NKN client.

Send and receive data between any NKN clients without setting up a server.

Note: This is a **client** version of the NKN protocol, which can send and
receive data but **not** relay data (mining). For **node** implementation which
can mine NKN token by relaying data, please refer to
[nkn](https://github.com/nknorg/nkn/).

**Note: This repository is in the early development stage and may not have all
functions working properly. It should be used only for testing now.**

## Usage

For npm:

```shell
npm install nkn-client
```

And then in your code:

```javascript
const nkn = require('nkn-client');
```

For browser, use `dist/nkn.js` or `dist/nkn.min.js`.

Create a client with a generated key pair:

```javascript
const client = nkn();
```

Or with an identifier (used to distinguish different clients sharing the same
key pair):

```javascript
const client = nkn({
  identifier: 'any string',
});
```

Get client key pair:

```javascript
console.log(client.key.seed, client.key.privateKey, client.key.publicKey);
```

Create a client using an existing seed:

```javascript
const client = nkn({
  identifier: 'any string',
  seed: '2bc5501d131696429264eb7286c44a29dd44dd66834d9471bd8b0eb875a1edb0',
});
```

By default the client will use bootstrap RPC server (for getting node address)
provided by us. Any NKN full node can serve as a bootstrap RPC server. To create
a client using customized bootstrap RPC server:

```javascript
const client = nkn({
  identifier: 'any string',
  seedRpcServerAddr: 'https://ip:port',
});
```

Private key should be kept **SECRET**! Never put it in version control system
like here.

Get client identifier:

```javascript
console.log(client.identifier);
```

And client NKN address, which is used to receive data from other clients:

```javascript
console.log(client.addr);
```

Listen for connection established:

```javascript
client.on('connect', () => {
  console.log('Connection opened.');
});
```

Send text message to other clients:

```javascript
client.send(
  'another client address',
  'hello world!',
);
```

You can also send byte array directly:

```javascript
client.send(
  'another client address',
  Uint8Array.from([1,2,3,4,5]),
);
```

Or publish text message to a topic (subscribe is done through [nkn-wallet-js](https://github.com/nknorg/nkn-wallet-js)):

```javascript
client.publish(
  'topic',
  0,
  'hello world!',
);
```
Receive data from other clients:

```javascript
// can also be async (src, payload, payloadType) => {}
client.on('message', (src, payload, payloadType) => {
  if (payloadType === nkn.PayloadType.TEXT) {
    console.log('Receive text message:', src, payload);
  } else if (payloadType === nkn.PayloadType.BINARY) {
    console.log('Receive binary message:', src, payload);
  }
});
```

If a valid data (string or Uint8Array) is returned at the end of the handler,
the data will be sent back to sender as response:

```javascript
client.on('message', (src, payload, payloadType) => {
  return 'Well received!';
  // You can also return a byte array:
  // return Uint8Array.from([1,2,3,4,5]);
});
```

Note that if multiple onmessage handlers are added, the result returned by the
first handler (in the order of being added) will be sent as response.

The `send` method will return a Promise that will be resolved when sender
receives a response, or rejected if not receiving acknowledgement within timeout
period. Similar to message, response can be either string or byte array:

```javascript
client.send(
  'another client address',
  'hello world!',
).then((response) => {
  // The response here can be either string or Uint8Array
  console.log('Receive response:', response);
}).catch((e) => {
  // This will most likely to be timeout
  console.log('Catch:', e);
});
```

Client receiving data will automatically send an acknowledgement back to sender
if no response is returned by any handler so that sender will be able to know if
the packet has been delivered. From the sender's perspective, it's almost the
same as receiving a response, except that the Promise is resolved without a
value:

```javascript
client.send(
  'another client address',
  'hello world!',
).then(() => {
  console.log('Receive ACK');
}).catch((e) => {
  // This will most likely to be timeout
  console.log('Catch:', e);
});
```

Timeout for receiving response or acknowledgement can be set when initializing
client:

```javascript
const client = nkn({
  responseTimeout: 5, // in seconds
});
```

or when sending a packet:

```javascript
client.send(
  'another client address',
  'Hello world!',
  {
    responseTimeout: 5, // in seconds
  },
)
```

Check [examples](examples) for full examples.

## Contributing

**Can I submit a bug, suggestion or feature request?**

Yes. Please open an issue for that.

**Can I contribute patches?**

Yes, we appreciate your help! To make contributions, please fork the repo, push
your changes to the forked repo with signed-off commits, and open a pull request
here.

Please sign off your commit. This means adding a line "Signed-off-by: Name
<email>" at the end of each commit, indicating that you wrote the code and have
the right to pass it on as an open source patch. This can be done automatically
by adding -s when committing:

```shell
git commit -s
```

## Community

* [Discord](https://discord.gg/c7mTynX)
* [Telegram](https://t.me/nknorg)
* [Reddit](https://www.reddit.com/r/nknblockchain/)
* [Twitter](https://twitter.com/NKN_ORG)
