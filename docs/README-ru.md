[![CircleCI Status](https://circleci.com/gh/nknorg/nkn-client-js.svg?style=shield&circle-token=:circle-token)](https://circleci.com/gh/nknorg/nkn-client-js)

# nkn-client-js

[English](/README.md) •
[Русский](/docs/README-ru.md)

JavaScript реализация NKN клиента.

Отправляйте и принимайте данные от любых NKN клиентов, без поднятии сервера.

Примечание: Это **клиентская** версия NKN протокола, которая может отправлять
и принимать данные, но **не** транслировать данные (майнинг). Для создания **узла**,
которая может майнить NKN токен через транслирование данных, пожалуйста, перейдите в
[nkn](https://github.com/nknorg/nkn/).

**Примечание: Этот репозиторий находится на ранней стадии разработки и могут
отсутствовать функции работающие должным образом. Он должен использоваться только
для тестирования**

## Применение

Установите через `npm`:

```shell
npm install nkn-client
```

И запустите свой код:

```javascript
const nkn = require('nkn-client');
```

Для браузеров используйте `dist/nkn.js` или `dist/nkn.min.js`.

Создайте клиент с помощью сгенерированных пар ключей:

```javascript
const client = nkn();
```

Или через идентификатор (используется, чтобы отличить разных клиентов с
одинаковыми парами ключей):

```javascript
const client = nkn({
  identifier: 'any string',
});
```

Получить пару ключей:

```javascript
console.log(client.key.privateKey, client.key.publicKey);
```

Создайте клиент, используя существующий приватный ключ:

```javascript
const client = nkn({
  identifier: 'any string',
  privateKey: 'cd5fa29ed5b0e951f3d1bce5997458706186320f1dd89156a73d54ed752a7f37',
});
```

По умолчанию, клиент использует загрузочный RPC сервер (чтобы получить адреса узлов)
предоставляемый нами. Любой полный узел NKN может быть использован, в качестве
загрузочного сервера. Чтобы создать клиент используя свой загрузочный RPC сервер,
используйте:

```javascript
const client = nkn({
  identifier: 'any string',
  seedRpcServerAddr: 'https://ip:port',
});
```

Приватный ключ должен хранится в **СЕКРЕТЕ**! Никогда не добавляйте его в систему
контроля версии, как здесь.

Получить идентификатор клиента:

```javascript
console.log(client.identifier);
```

И адрес NKN клиента, которая используется для получения данных с других клиентов:

```javascript
console.log(client.addr);
```

Событие при установке соединения:

```javascript
client.on('connect', () => {
  console.log('Connection opened.');
});
```

Отправить текстовое сообщение другим клиентам:

```javascript
client.send(
  'another client address',
  'hello world!',
);
```

Также, вы можете напрямую отправить массив байтов:

```javascript
client.send(
  'another client address',
  Uint8Array.from([1,2,3,4,5]),
);
```

Получить данные с других клиентов:

```javascript
// Также, можно запустить асинхронно
// async (src, payload, payloadType) => {}
client.on('message', (src, payload, payloadType) => {
  if (payloadType === nkn.PayloadType.TEXT) {
    console.log('Receive text message:', src, payload);
  } else if (payloadType === nkn.PayloadType.BINARY) {
    console.log('Receive binary message:', src, payload);
  }
});
```

Если в конце обработчик получил валидные данные (string или Uint8Array),
эти данные будут переданы обратно отправителю, в качестве ответа:

```javascript
client.on('message', (src, payload, payloadType) => {
  return 'Well received!';
  // Также, вы можете вернуть массив байтов
  // return Uint8Array.from([1,2,3,4,5]);
});
```

Обратите внимание, что если в onmessage переданы несколько обработчиков, результат
от первого завершенного обработчика (в добавленном порядке) будет отправлен,
в качестве ответа.

Метод `send` вернет Promise, который будет выполнен, когда отправитель получит
ответ, или если отправитель отклонил ответ, или не ответил в течение заданного таймаута.
Подобно сообщению, ответ может быть строкой или массивом байтов.

```javascript
client.send(
  'another client address',
  'hello world!',
).then((response) => {
  // Здесь ответом может быть string или Uint8Array
  console.log('Receive response:', response);
}).catch((e) => {
  // Скорее всего, здесь будет таймаут
  console.log('Catch:', e);
});
```

Если ни один обработчик не вернет результат, клиент автоматический
отправит подтверждение отправителю, так отправитель сможет узнать, если
данные были доставлены. Для отправителя это будет точно также, как если бы
он получил ответ, за исключением, что Promise завершится успешно
без каких-либо значении:

```javascript
client.send(
  'another client address',
  'hello world!',
).then(() => {
  console.log('Receive ACK');
}).catch((e) => {
  // Скорее всего, здесь будет таймаут
  console.log('Catch:', e);
});
```

Таймаут ожидания ответа или подтверждения может быть установлен, при
инициализации клиента:

```javascript
const client = nkn({
  responseTimeout: 5, // в секундах
});
```

или при отправке данных:

```javascript
client.send(
  'another client address',
  'Hello world!',
  {
    responseTimeout: 5, // в секундах
  },
)
```

Посмотрите [примеры](examples) для полного понимания.

## Внести вклад

**Могу ли я уведомить, об ошибке или предложить улучшения?**

Да. Для этого откройте `issue`, пожалуйста!

**Могу ли я внести исправления?**

Да, мы ценим вашу помощь! Чтобы внести свой вклад, пожалуйста,
форкните репозиторий, запушьте изменения в форкнутый репозиторий с
подписанными коммитами и откройте `pull request` здесь.

Пожалуйста, подписывайте свой коммит. Это значит, добавлять строку, в виде
"Signed-off-by: Name <email>", в конце каждого коммита подтверждая,
что код написан вами и у вас есть права передать его, как исправления с открытым
исходным кодом. Это можно добавлять автоматический добавив `-s`, при коммите:

```shell
git commit -s
```

## Сообщество

* [Discord](https://discord.gg/c7mTynX)
* [Telegram](https://t.me/nknorg)
* [Reddit](https://www.reddit.com/r/nknblockchain/)
* [Twitter](https://twitter.com/NKN_ORG)
