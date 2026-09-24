# LingQiongBuddy

> 一个把「AI 会操作手机文件」做出来的 Android 小应用。
> 原理：模型只输出结构化文本（工具调用请求），真正的文件读写由 App 的 Java 桥接层执行。

- **应用名**：LingQiongBuddy
- **版本**：2.0.0（versionCode 2）
- **包名**：`com.lingqiong.buddy`
- **minSdk**：26 ／ **targetSdk**：34

---

## 一、它是什么

LingQiongBuddy 用一个 WebView 承载全部 UI（`app/src/main/assets/index.html`），
网页通过 `addJavascriptInterface` 调用原生 Java，从而实现：

- 对话式调用大模型（DeepSeek 兼容 `chat/completions`，支持流式、思考、图片、文档）
- **Function Calling 工具循环**：读文件、写文件、列目录、复制/移动、执行 shell 等
- **Shizuku** 高权限通道：以 adb/root 身份访问受限目录、执行任意命令

```
用户提问
  → 网页把「工具清单 + 对话」发给模型
  → 模型返回 tool_calls（一段 JSON 文本，不是执行结果）
  → 网页解析后调用 Java 桥接，在手机上真正执行
  → 执行结果作为 role:"tool" 消息回喂模型
  → 模型据此继续，循环直到任务完成
```

Java 从来没有"在 HTML 里运行"：两者分别跑在 ART 与 WebView(V8) 里，
`addJavascriptInterface` 注册的只是一个"代理门"，JS 访问 `window.AndroidFile.xxx()`
会经 WebView native 拦截 → JNI → 反射，最终落到 Java 方法上。

---

## 二、2.0.0 更新内容

1. **设置分层**
   - 新增「总设置」（右上齿轮）：全局生效。
   - 原有参数移入「对话设置」（右上滑杆图标）：**仅作用于当前对话**，各对话互不影响。
2. **总设置新增字体大小调节**：实时生效，全 App 文字缩放。
3. **总设置新增备份 / 还原**
   - 备份：把配置 + 全部对话打包成一个 JSON 文件，可自定义文件名。
   - 文件存放在根目录固定文件夹 `/sdcard/LingQiongBuddy/备份/`，**卸载 App 也不会被删除**。
   - 还原：列出所有备份文件，选择其一覆盖还原。
4. **工具调用展示优化**：不再一条条堆在气泡里，而是收进一个可上下滑动的盒子（与"思考过程"同款样式）。
5. **思考默认中文**：系统提示会要求模型用简体中文思考，减少默认英文思考（可在总设置关闭）。
6. **删除 → 回收站**
   - AI 的删除动作改为"移入回收站" `/sdcard/LingQiongBuddy/回收站/`。
   - 总设置里可对回收站文件「还原」或「永久删除」。
   - AI 默认不具备永久删除能力；只有在「对话设置」打开 **允许永久删除** 后，才会获得 `permanent_delete_file` 工具，用于处理必须删除的文件。
7. **修复中断对话后的错误与"AI 自救"**：用户点停止时不再触发自救重试，也不会显示报错。
8. **新增「继续生成」**：中断或出错后，气泡下方会出现按钮，可从断点继续，不重复已输出内容。
9. 应用名改为 **LingQiongBuddy**，应用图标替换为 `res/drawable/app_icon.png`，版本号升级为 **2.0.0**。

---

## 三、目录结构

```
LingQiongBuddy-2.0.0/
├── settings.gradle
├── build.gradle
├── gradle.properties
├── gradle/wrapper/gradle-wrapper.properties
├── .gitignore
├── README.md
└── app/
    ├── build.gradle
    └── src/main/
        ├── AndroidManifest.xml
        ├── assets/index.html                 # 全部 UI 与逻辑
        ├── java/com/lingqiong/buddy/
        │   ├── MainActivity.java             # WebView + 桥接注册
        │   ├── FileBridge.java               # 普通权限文件桥接
        │   └── ShizukuBridge.java            # 高权限 shell 桥接
        └── res/drawable/app_icon.png         # 应用图标
```

---

## 四、构建

### 方式 A：Android Studio（推荐）
1. 用 Android Studio 打开本目录（`LingQiongBuddy-2.0.0`）。
2. 等待 Gradle Sync（会自动下载 Gradle Wrapper 与依赖）。
3. `Build > Build Bundle(s) / APK(s) > Build APK(s)`。

### 方式 B：命令行
```bash
# 首次可先生成 wrapper（需本机已装 Gradle 8.x）
gradle wrapper
./gradlew assembleDebug
# 产物：app/build/outputs/apk/debug/app-debug.apk
```

> 依赖：AGP 8.1.4、JDK 17、Shizuku 库 `dev.rikka.shizuku:api/provider:13.1.5`。

---

## 五、使用说明

1. 首次启动会申请「所有文件访问权限」，请授予。
2. 打开 **总设置** → 填写 **API Key**（DeepSeek）。
3. （可选）安装 [Shizuku](https://shizuku.rikka.app/) 并授权，即可访问受限目录 / 执行 shell。
4. 右上 **对话设置** 调整本对话的模型、温度、系统提示、是否允许删除等。
5. 右上 **总设置** 调整字体、备份还原、回收站、全局参数。

---

## 六、安全提示

- `shell_exec` + `rm -rf` 有能力删除整个存储区，请谨慎授予 Shizuku。
- 删除默认进回收站；「永久删除」是危险开关，默认关闭。
- 备份文件存放在 `/sdcard/LingQiongBuddy/` 下，注意其中包含 API Key，请勿随意分享。

---

## License

仅供学习交流使用。

---

## 七、在 GitHub 上自动打包 APK

本仓库自带 `.github/workflows/build.yml`：

- 推送到 `main` / `master` 时自动构建，也可以在 Actions 页面手动 `Run workflow`。
- 构建完成后，在该次运行的 **Artifacts** 里下载 `LingQiongBuddy-2.0.0-debug.zip`，解压即是 **可直接安装的 APK**。

> 注意：本工程**没有** `gradlew`，所以工作流直接用 `gradle` 命令构建（Gradle 8.2）。
> 若你自己写了用到 `./gradlew` 的工作流，会因缺少 wrapper 而失败——需要先在本地 `gradle wrapper` 生成包装器。

## 八、把本地工程整体替换到已有仓库

手机上已装 Termux 时，执行：

```bash
bash /sdcard/update-repo.sh https://github.com/你的用户名/你的仓库.git
```

该脚本会：克隆仓库 → 清空除 `.git` 外的旧文件 → 复制本工程 → 提交 → 推送。
