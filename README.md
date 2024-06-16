# **Social Recovery Of Smart Wallet Contracts**

Diploma work 

## **Testing**

First, compile the contract:

```
$ forge compile
```

Then run the tests:

```
$ forge test --gas-report
```

1. Скачать зависимости
2. Деплой необходимых кошельков. Может понадобиться убрать package.json - "type": "module",
3. Создание смарт кошелька и включение модуля SocialRecovery

```
$ npm install
$ npx hardhat deploy --network localhost
$ npx hardhat run run_scripts/main.js
```

## License
-------
All smart contracts are released under LGPL-3.0