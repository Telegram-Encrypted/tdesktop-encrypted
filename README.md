 
# Telegram Desktop Encrypted

  

This project is an attempt to bring secret chat support to telegram desktop. It's still under heavy development but it's capable of sending / receiving encrypted text messages over secret chats.
Based on the [Telegram API][telegram_api] and the [MTProto][telegram_proto] secure protocol, no tdlib.
  

[![Preview of Telegram Desktop][preview_image]][preview_image_url]


The source code is published under GPLv3 with OpenSSL exception, the license is available [here][license].

## Progress

 - [x] Accept incoming secret chats, key exchange.
 - [x] Decrypt incoming messages, encrypt outgoing messages.
 - [x] A simple UI that can handle sending & receiving text messages.
 - [x] Proper & Secure storage of chats and messages.
 - [x] Support text formatting, replies, contact mapping.
 - [x] Support read receipts, typing events.
 - [x] Initiate secret chat from client.
 - [ ] Support stickers, documents, media.
 - [ ] Support forwarding a message into secret chat.
 - [ ] Handle delete message & chat events.
 - [ ] Handle key rotation.
 - [ ] Handle notifications.
 - [ ] Handle periodic chat clear. 

#### Future wishes
 - [ ] Create encrypted group chats that works the same way with SimpleX group chat logic, by rendering seperate 
 - [ ] Bring encryption to standard chats to make use of telegram cloud, but don't know if this is possible without violating telegram's client api user agreement.



  

## Supported systems

  
Development is done under windows and linux, proper binary releases are coming soon.
  

## Third-party

  

* Qt 6 ([LGPL](http://doc.qt.io/qt-6/lgpl.html)) and Qt 5.15 ([LGPL](http://doc.qt.io/qt-5/lgpl.html)) slightly patched

* OpenSSL 3.2.1 ([Apache License 2.0](https://www.openssl.org/source/apache-license-2.0.txt))

* WebRTC ([New BSD License](https://github.com/desktop-app/tg_owt/blob/master/LICENSE))

* zlib ([zlib License](http://www.zlib.net/zlib_license.html))

* LZMA SDK 9.20 ([public domain](http://www.7-zip.org/sdk.html))

* liblzma ([public domain](http://tukaani.org/xz/))

* Google Breakpad ([License](https://chromium.googlesource.com/breakpad/breakpad/+/master/LICENSE))

* Google Crashpad ([Apache License 2.0](https://chromium.googlesource.com/crashpad/crashpad/+/master/LICENSE))

* GYP ([BSD License](https://github.com/bnoordhuis/gyp/blob/master/LICENSE))

* Ninja ([Apache License 2.0](https://github.com/ninja-build/ninja/blob/master/COPYING))

* OpenAL Soft ([LGPL](https://github.com/kcat/openal-soft/blob/master/COPYING))

* Opus codec ([BSD License](http://www.opus-codec.org/license/))

* FFmpeg ([LGPL](https://www.ffmpeg.org/legal.html))

* Guideline Support Library ([MIT License](https://github.com/Microsoft/GSL/blob/master/LICENSE))

* Range-v3 ([Boost License](https://github.com/ericniebler/range-v3/blob/master/LICENSE.txt))

* Open Sans font ([Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0.html))

* Vazirmatn font ([SIL Open Font License 1.1](https://github.com/rastikerdar/vazirmatn/blob/master/OFL.txt))

* Emoji alpha codes ([MIT License](https://github.com/emojione/emojione/blob/master/extras/alpha-codes/LICENSE.md))

* xxHash ([BSD License](https://github.com/Cyan4973/xxHash/blob/dev/LICENSE))

* QR Code generator ([MIT License](https://github.com/nayuki/QR-Code-generator#license))

* CMake ([New BSD License](https://github.com/Kitware/CMake/blob/master/Copyright.txt))

* Hunspell ([LGPL](https://github.com/hunspell/hunspell/blob/master/COPYING.LESSER))

* Ada ([Apache License 2.0](https://github.com/ada-url/ada/blob/main/LICENSE-APACHE))

  

## Build instructions

  

* Windows [(32-bit)][win32] [(64-bit)][win64]

* [macOS][mac]

* [GNU/Linux using Docker][linux]

  

[//]: #  (LINKS)

[telegram]: https://telegram.org

[telegram_desktop]: https://desktop.telegram.org

[telegram_api]: https://core.telegram.org

[telegram_proto]: https://core.telegram.org/mtproto

[license]: LICENSE

[win32]: docs/building-win.md

[win64]: docs/building-win-x64.md

[mac]: docs/building-mac.md

[linux]: docs/building-linux.md

[preview_image]: https://github.com/Telegram-Encrypted/tdesktop-encrypted/blob/experimental/docs/assets/preview2.png  "Preview of Telegram Desktop"

[preview_image_url]: https://raw.githubusercontent.com/Telegram-Encrypted/tdesktop-encrypted/experimental/docs/assets/preview2.png

