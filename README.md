# Secure Notebook

"A sandbox is implemented by executing the software in a restricted operating system environment, thus controlling the resources (e.g. file descriptors, memory, file system space, etc.) that a process may use.[4]" - Wikipedia

- run jupyter notebooks securely using macOS's native sandboxing
- https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox
- 
  - "Sandboxing is enforced by the kernel and present on both macOS and Apple’s iOS-based operating systems"
  - 'The implementation details of sandboxing are not intended to be accessed by third-party developers, but applications on Apple’s platforms can request' 
  - https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/
- https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf
- https://developer.apple.com/documentation/Xcode/configuring-the-macos-app-sandbox?language=objc
- inspired by (node-safe)[https://github.com/berstend/node-safe]

Using the definition from Apple’s website:
“Sandboxing protects the system by limiting the kinds of operations an application
can perform, such as opening documents or accessing the network. Sandboxing
makes it more difficult for a security threat to take advantage of an issue in a
specific application to affect the greater system.”

- https://7402.org/blog/2020/macos-sandboxing-of-folder.html
