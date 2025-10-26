Java.perform(function () {
  var classObj = Java.use("");

  try {
    classObj.methodName.implementation = function (arg1) {
      console.log("\n[*] ");
    };
  } catch (e) {}
});
