---
layout: post
title: Gantix JailMonkey Root Detection Bypass
---

[jail-monkey][jail-monkey] is a React Native for implementing root detection
on Android and iOS devices which is not defeated by the default root detection
bypass implemented by [objection][objection].

The jail-monkey API is a set of methods exposed to a React Native app through
the `JailMonkey` module.


```js
import JailMonkey from 'jail-monkey'

// is this device JailBroken on iOS/Android?
JailMonkey.isJailBroken()

// Can this device mock location - no need to root!
JailMonkey.canMockLocation()

// Check if device violates any of the above
JailMonkey.trustFall()

// (ANDROID ONLY) Check if application is running on external storage
JailMonkey.isOnExternalStorage()

// (ANDROID ONLY) Check if the phone has some malicious apps installed
JailMonkey.hookDetected()

// Check if the application is running in debug mode
JailMonkey.isDebugged()
```

On Android, the check is implemented in the
[`JailMonkeyModule`](https://github.com/GantMan/jail-monkey/blob/master/android/src/main/java/com/gantix/JailMonkey/JailMonkeyModule.java)
Java class with the following method:

```java
@Override
public @Nullable
Map<String, Object> getConstants() {
    ReactContext context = getReactApplicationContext();
    final Map<String, Object> constants = new HashMap<>();
    constants.put("isJailBroken", isJailBroken(context));
    constants.put("hookDetected", hookDetected(context));
    constants.put("canMockLocation", isMockLocationOn(context));
    constants.put("isOnExternalStorage", isOnExternalStorage(context));
    constants.put("AdbEnabled", AdbEnabled(context));
    return constants;
}
```

It is possible to bypass the detection with the following Frida script that
instruments the `getConstants` method and returns a map with all keys set to
false.

```js
/**
Root detection bypass script for Gantix JailMoney
https://github.com/GantMan/jail-monkey
**/
Java.perform(() => {
    const klass = Java.use("com.gantix.JailMonkey.JailMonkeyModule");
    const hashmap_klass = Java.use("java.util.HashMap");
    const false_obj = Java.use("java.lang.Boolean").FALSE.value;

    klass.getConstants.implementation = function () {
        var h = hashmap_klass.$new();
        h.put("isJailBroken", false_obj);
        h.put("hookDetected", false_obj);
        h.put("canMockLocation", false_obj);
        h.put("isOnExternalStorage", false_obj);
        h.put("AdbEnabled", false_obj);
        return h;
    };
});
```

On iOS, the check is implemented in the
[`JailMonkey`](https://github.com/GantMan/jail-monkey/blob/master/JailMonkey/JailMonkey.m)
Objective-C class with the following method:

```objective-c
- (NSDictionary *)constantsToExport
{
	return @{
		JMisJailBronkenKey: @(self.isJailBroken),
		JMCanMockLocationKey: @(self.isJailBroken)
	};
}
```

The `constantsToExport` method calls out to the following method:

```objective-c
- (BOOL)isJailBroken{
    #if TARGET_OS_SIMULATOR
      return NO;
    #endif
    return [self checkPaths] || [self checkSchemes] || [self canViolateSandbox];
}
```

It is possible to bypass the detection with the following Frida script that
instruments the `isJailBroken` method to returns false.


```js
/**
Root detection bypass script for Gantix JailMoney
https://github.com/GantMan/jail-monkey
**/
const klass = ObjC.classes.JailMonkey;
Interceptor.attach(klass['- isJailBroken'].implementation, {
    onLeave: function (retval) {
        retval.replace(0);
    }
});
```

Both Frida scripts will be maintained in my [frida-scripts][frida-scripts]
GitHub repository in the following files:

1. android/gantix_jailmonkey_bypass.js
2. ios/gantix_jailmonkey_bypass.js


[jail-monkey]: https://github.com/GantMan/jail-monkey
[objection]: https://github.com/sensepost/objection
[frida-scripts]: https://github.com/Ayrx/frida-scripts
