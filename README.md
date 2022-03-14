# How to launch a bot
## Clone AyzekReborn
```git clone git@github.com:AyzekReborn/AyzekReborn.git```

## Clone UniqueNetwork plugin for AyzekReborn
To connect the plugin, you need to clone it to a folder packages:
```sh
cd packages
git clone git@github.com:UniqueNetwork/ayzek-plugin-unique.git
```

## Build
```sh
yarn
yarn build:dev
```
The **build:dep** command runs in the background, it does not need to be restarted.

And in a separate terminal:
```sh
mkdir dist/config
yarn run:dev
```
**run:dev** similarly, the bot automatically loads all changes in plugins. But **run:dev** needs to be restarted when configs change.

## Configure bot
First stop **run:dev** by pressing **CTRL+C**.

Go to **dist/config**, there for all the APIs that you don't use, change **local** to an empty array.

### Telegram example
Edit TelegramAPIPlugin.yaml like:
```yaml
local:
  - descriminator: telegramExample
    username: name_bot
    token: 1234567890:abcdeEFGHIJKlmnopQRSTUVwxyzABCDefgh
```
Start **run:dev** again.