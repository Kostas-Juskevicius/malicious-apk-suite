Java.perform(function () {
  var classObj = Java.use(""); // note: fully qualified class name

  // note: frida crashes on exception. keep it running via try-catch block
  try {
    classObj.methodName.implementation = function (arg1) {
      console.log("\n[*] OVERRIDEN IMPLEMENTATION");
    };
  } catch (e) {}
});
