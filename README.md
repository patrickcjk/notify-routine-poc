# notify-routine-poc
PsSetCreateProcessNotifyRoutine bypass proof-of-concept for manual mapped drivers

## Why
If you ever tried to use PsSetCreateThreadNotifyRoutine in a manual mapped driver (without creating a driver object) they you must know the call fails and returns STATUS_ACCESS_DENIED. This is because the function calls MmVerifyCallbackFunctionCheckFlags which checks that the address of the notify routine you want to register is in the range of a legit module. Which will fail if you don't create a driver object (or load your driver right way!).

## How
That being said, PsSetCreateThreadNotifyRoutine will succeed if NotifyRoutine is in ANY legit module. This proof-of-concept will iterate loaded drivers and scan for a code cave where we can write a trampoline to our real routine (located in our manual mapped driver).

## Pros
- You can very easily port this code to work with other similar functions such as PsSetLoadImageNotifyRoutine and PsSetCreateThreadNotifyRoutine.
- This will not trigger patch guard as the notify routine start address will be in a legit module

## Cons
- We are writing a trampoline in the .text section of a legit driver, this will get you banned or at the very least flagged on ring-0 anti cheats such as BattlEye and EasyAntiCheat.

<p align="center"><img src="https://i.gyazo.com/7c980e6519401e60c4fa82d7c845556a.png" /></p>
