# LingQiongBuddy

> 一个把「AI 会操作手机文件 / 跑终端命令」做出来的 Android 小应用。
> 原理：模型只输出结构化文本（工具调用请求），真正的执行由 App 的 Java 桥接层完成。

- **应用名**：LingQiongBuddy
- **版本**：2.3.1（versionCode 6）
- **applicationId**：`com.lq.app`（10 字节，与官方 `com.termux` 等长，见下方说明）
- **代码包名(namespace)**：`com.lingqiong.buddy`
- **minSdk**：26 ／ **targetSdk**：28 ⚠️（见下方说明）

---

## ★ 三个必须知道的"反常识"设定

### 1. 为什么 applicationId 是 `com.lq.app`？—— 与官方 Termux 共存

Termux 的 bootstrap 里，**每个二进制的库搜索路径都被编译期硬编码成**：

```
/data/data/com.termux/files/usr/lib
```

如果直接用 `com.termux` 当包名，本 App 就和官方 Termux **同包名、签名不同、无法共存**。

所以本 App 使用 **`com.lq.app`**（正好也是 10 字节）。CI 打包时会下载官方 bootstrap，
把里面所有 `com.termux` **等长替换**成 `com.lq.app`（等长 ⇒ ELF 内部字符串偏移不变 ⇒ 二进制不损坏）。
于是：

- `getFilesDir()` 就是 `/data/data/com.lq.app/files`，环境完全属于本 App；
- `applicationId ≠ com.termux` ⇒ **与官方 Termux 可以同时安装、互不干扰**；
- **把官方 Termux 卸载了，本 App 的终端照样能跑**。

> 想换包名：改成任意 **10 个字符**的包名即可，并同步改 `.github/workflows/build.yml` 里的 `APP_ID`。

### 2. 为什么 targetSdk 必须是 28？

Android 10(Q) 起，系统**只禁止 `targetSdk >= 29` 的应用从私有目录执行二进制**（W^X 策略）。
`targetSdk = 28` 可豁免，Termux 官方也是这么做的。若改成 29+，终端会直接无法运行。

### 3. 多环境"完全隔离"是怎么做到的？（不需要 proot）

硬编码的库路径只有一份 `/data/data/com.lq.app/files/usr`，所以这里用**符号链接激活**：

```
files/envs/<环境id>/usr     每个环境一套【完整 bootstrap】——独立软件库
files/envs/<环境id>/home    每个环境独立 HOME
files/usr                   指向"当前激活环境"usr 的软链
```

执行命令前，把 `files/usr` 软链指向目标环境的 usr，二进制便自然加载该环境自己的库。
因此**每个环境都能各自 `pkg install` 不同版本的软件**（例如两个环境装不同 Python）。

- 不需要 proot、不需要额外二进制，兼容所有机型；
- 同一时刻只有一个环境被"激活"（AI 单对话场景完全够用）；
- 切换环境只是改一条软链，瞬间完成。

---

## 一、2.3.1 更新内容

1. **修复「终端」按钮点了没反应** ⭐
   聊天页顶部的「终端」按钮此前**根本没有绑定点击事件**（`openTermSheet()` 定义了却无人调用），
   所以点了毫无反应。现已补上绑定，并让遮罩、关闭按钮都能正常关闭终端面板。

2. **视频真正“看得见”了** ⭐
   以前发视频只把**文件路径**交给 AI，AI 其实看不到画面。现在发送视频时会自动用 ffmpeg
   把画面**按时间顺序均匀抽成 N 张关键帧图片**（默认 16 张，可在
   **对话设置 → 视频抽帧数** 里调 10–30），作为图片随消息一起送给 AI，AI 便能直接观察画面。
   若环境里没有 ffmpeg，会在消息里提示先 `pkg install ffmpeg`。

3. **修复 `pkg install` 完全不可用** ⭐
   官方源里每个 `.deb` 内部仍写死了 `com.termux`（含 ELF 的 RUNPATH），
   导致安装任何新软件都失败（`unable to stat './data/data/com.termux' ... Permission denied`）。
   现在每个环境里都内置了 `patch-debs` 钩子 + `apt.conf.d/99-lq-prefix.conf`：
   apt 安装前把 deb 内的 `com.termux` 等长替换为本 App 包名，`pkg install` 恢复正常。

4. 版本号升级为 **2.3.1**（versionCode 6）。

### 2.3.0 更新内容

1. **修复"发消息时界面卡死"** ⭐
   以前终端/Shizuku 命令是**同步**执行（在 WebView 的 JS 线程上 `waitFor`），
   一旦命令长时间不返回（`pkg install`、交互式命令、卡死的命令），整个界面就会冻结：
   按钮失灵、无法滑动，但原生输入框光标仍在闪。
   现在全部改为 **异步执行 + 轮询 + 超时兜底**（`execStart` / `execPoll` / `execKill`），
   命令再慢也不会阻塞界面。
2. **多环境改为「完全隔离」** ⭐
   每个环境一套独立的完整软件库（见上文），可各自安装不同版本的软件。
   总设置里新建/删除环境，对话设置里为不同对话选择不同环境。
3. **备份可包含完整 Termux 环境** ⭐
   「总设置 → 备份」新增开关「同时备份完整 Termux 环境」：
   开启后会把每个环境里 `pkg` 安装的全部软件打包成 `.env.tar.gz`（体积可达数百 MB），
   换机后可完整还原；关闭则只备份配置与各环境工作目录里的文本文件。
   还原时会自动识别并还原 `.env.tar.gz`。
4. **升级兼容**：从旧版升级时，旧环境（共用一份 usr）会自动收敛为 `default` 环境。
5. 版本号升级为 **2.3.0**（versionCode 5）。

### 2.1.0 / 2.0.0 已有的能力（沿用）

- **内置 Termux 终端环境（自包含）**：App 自带一份完整 Termux，与手机上的 Termux App 无关。
- **多环境管理**：总设置里创建环境、对话设置里选择环境。
- **终端页面**：聊天页顶部「终端」按钮打开，可切换环境、执行命令、查看回显。
- **API Key 在「对话设置」**（全局共用）。
- **视频上传**：视频不读进内存（多大都行），只把真实路径交给 AI；同时自动抽帧成图片让 AI 直接观察画面。
- 设置分层：总设置（全局）／对话设置（仅当前对话）。
- 字体大小调节、备份与还原（存 `/sdcard/LingQiongBuddy/备份/`，卸载不丢）。
- 工具调用收进可滑动的盒子；思考默认中文。
- 删除 → 移入回收站（`/sdcard/LingQiongBuddy/回收站/`），可还原/永久删除；
  AI 默认无永久删除权限，需在对话设置里打开。
- 修复中断后的"AI 自救"误报，新增「继续生成」。

---

## 二、内置终端是怎么实现的

```
打包阶段（GitHub Actions）
  └─ 下载 termux-packages 的 bootstrap-aarch64.zip
     → 把 "com.termux" 等长替换为 "com.lq.app" → app/src/main/assets/

首次运行
  └─ TermuxBridge.install()
       ├─ 解压 zip 到 files/envs/default/usr（每个环境一份）
       ├─ 重建 SYMLINKS.txt 里的符号链接
       ├─ chmod 0755（Termux 的脚本/二进制都需要可执行位）
       └─ 写入 patch-debs 钩子 + apt.conf.d/99-lq-prefix.conf（让 pkg install 可用）

执行命令（异步）
  └─ JS: termuxExecStart() → Java execStart() 立即返回任务号
         Java: 后台线程 activate(env) + ProcessBuilder(bash -c cmd) + 读输出
     JS: termuxExecPoll(任务号) 每 250ms 轮询 → 直到 done
```

- AI 侧工具：`termux_exec(cmd, env)`、`shell_exec(cmd)`
- 用户侧：聊天页「终端」按钮 → 选择环境 → 输入命令 → 查看输出

---

## 三、目录结构

```
LingQiongBuddy-2.3.1/
├── .github/workflows/build.yml          # 自动下载 bootstrap、等长替换包名、打包 APK
├── settings.gradle / build.gradle / gradle.properties
├── gradle/wrapper/gradle-wrapper.properties
├── .gitignore / README.md
└── app/
    ├── build.gradle                     # applicationId=com.lq.app, targetSdk=28
    └── src/main/
        ├── AndroidManifest.xml
        ├── assets/index.html            # 全部 UI 与逻辑
        ├── java/com/lingqiong/buddy/
        │   ├── MainActivity.java        # WebView + 桥接注册 + 文件路径回传
        │   ├── FileBridge.java          # 普通权限文件桥接
        │   ├── ShizukuBridge.java       # 高权限 shell 桥接（异步）
        │   └── TermuxBridge.java        # ★ 自包含 Termux + 多环境（异步）
        └── res/drawable/app_icon.png
```

---

## 四、构建

### 方式 A：GitHub Actions（推荐，不需要本地环境）
推送后自动构建，产物在本次运行的 **Artifacts** 里（`LingQiongBuddy-2.3.1-debug`）。
工作流会自动下载 Termux bootstrap、等长替换包名后打进 APK。

### 方式 B：Android Studio
1. 打开本目录 → 等待 Sync。
2. **先把 `bootstrap-aarch64.zip` 放进 `app/src/main/assets/`**（本仓库不入库这个大文件）。
   可手动下载：`termux/termux-packages` 的 releases 里找 `bootstrap-aarch64.zip`。
3. `Build > Build APK(s)`。

### 方式 C：命令行
```bash
gradle wrapper      # 本仓库没有 gradlew，可先生成
./gradlew assembleDebug
```

---

## 五、使用说明

1. 首次启动授予「所有文件访问权限」。
2. **总设置 → Termux 环境 → 安装**，等待解压完成（约几十秒）。
3. **对话设置 → 填写 API Key**（DeepSeek）。
4. 需要多套不同版本软件时：**总设置 → Termux 环境 → 新建环境**（会各自解压一份基础环境），
   然后到 **对话设置 → 使用的 Termux 环境** 为不同对话分别选择。
5. （可选）装上 Shizuku 并授权，获得更高级的文件访问能力。
6. 聊天页「终端」按钮可自己敲命令；AI 也会按需调用 `termux_exec`。

---

## 六、安全提示

- 内置终端拥有 App 私有目录的完整读写权，`rm -rf` 很危险，请谨慎。
- 删除默认进回收站；「永久删除」是危险开关，默认关闭。
- 备份文件包含 API Key，请勿随意分享。
- 删除某个环境会**一并删除它独立安装的全部软件**，不可恢复。

---

## License

仅供学习交流使用。
