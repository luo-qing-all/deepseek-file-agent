# LingQiongBuddy

> 一个把「AI 会操作手机文件 / 跑终端命令」做出来的 Android 小应用。
> 原理：模型只输出结构化文本（工具调用请求），真正的执行由 App 的 Java 桥接层完成。

- **应用名**：LingQiongBuddy
- **版本**：2.5.0（versionCode 23）
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

## 更新日志

### 2.4.3（versionCode 19）

- **修复「打断/出错后失忆」**：此前只有手动停止会归档；网络中断或出错时，那条 AI 回复不会写入历史，导致下一轮「失忆」（典型表现：明明只输出到第 28 条，下一轮却答「第 100 条」）。
- 现在**中断或出错都会把已输出的内容归档进历史**，保证历史与界面一致。
- 归档时若整条都是错误提示，则视为无内容，**不污染历史**。
- 版本号 **2.4.3**（versionCode 19）。

### 2.4.2（versionCode 18）

- **对话续写更自然（贴近 DeepSeek 官方客户端）**：点「继续生成」时**复用同一个气泡**、正文原地累积；把已输出内容作为 assistant 前缀发回模型，从断点自然接续，不再重复、不再重来。
- **修复对话历史污染**：不再向历史插入假消息「（继续）」；续写结果与上文合并为**一条** assistant 消息，历史始终保持 user/assistant 交替的干净结构。
- **跨轮记忆（记得做过什么）**：每条 assistant 历史消息附带**本轮工具调用摘要**（调用了什么工具、参数、结果片段），下一轮对话时模型能看到之前搜过/读过/做过什么，不再「从头再来」。
- **联网搜索收敛为抓取版**：确认代码中只保留「内置 Termux + 360 搜索抓正文」的实现（早前基于 DeepSeek Responses API 的接口方案已移除）。
- 版本号 **2.4.2**（versionCode 18）。

### 2.4.1（versionCode 17）

- **恢复「允许永久删除」开关**（对话设置 → 工具权限）：默认**关闭** —— AI 删除一律移入回收站；打开后 AI 才可真正永久删除（不可恢复）。
- **新增 rm 硬守卫**：开关关闭时，连内置 Termux 里的 `rm` 命令也被拦截 —— 删除 `/sdcard`、`/storage` 下的文件会被自动移入回收站；其它路径（如 `$PREFIX` 系统目录）照常放行，不影响 `pkg` 等操作。App 启动时自动安装/校验（`usr/bin/rm` 包装脚本 + `usr/bin/.lqb-bin/rm` 真删代理），无需手动干预。
- **删除策略文件**：开关状态同步写入 `/sdcard/LingQiongBuddy/.delete_policy`（`allow` / `recycle`），App 对话与终端 `rm` 共用同一策略。
- **保留**：对话设置、总设置两个入口按钮；「联网搜索」「文件读写」维持**永久开启**（不设开关）。
- **新对话首页 UI**：蓝紫渐变背景 + 重绘居中「LQ」图标（多层渐变 / 高光 / 呼吸浮动动画）。
- 版本号 **2.4.1**（versionCode 17）。

### 2.4.0（versionCode 14）

- 新增「联网搜索」开关：开启后改用 DeepSeek **Responses API**（`/responses`）并声明 `web_search` 工具，由服务端尝试联网搜索、返回带引用的回答；关闭则回到原来的 Chat Completions。
- 适配 Responses API 的流式事件（`response.output_text.delta` / `response.reasoning_text.delta` / `response.output_item.done` / `response.web_search_call.*` / `response.completed` 等）。
- 工具调用在 Responses 模式下以 `function_call` / `function_call_output` 回传。
- 版本号升级为 **2.4.0**（versionCode 14）。
- **新增「断流自动重试」**：网络波动导致响应流中断（`network error`）时，App 会自动回滚并重连，最多重试 3 次（指数退避），不再直接把错误抛给用户；仅在真正解析成功后重置计数，避免无限重试。

### 2.3.4（versionCode 9）

本次更新应用图标与整体界面视觉。

1. **更换应用图标** ⭐
   图标替换为指定图片：自动居中裁剪为正方形并缩放到 512×512，覆盖 `res/drawable/app_icon.png`。
2. **界面视觉全面升级** ⭐
   - 统一设计令牌（圆角 / 阴影 / 间距 / 配色），主色改为柔和渐变；
   - 统一动画曲线（缓出、弹簧、抽屉曲线）：按钮按压回弹、开关与滑块更顺滑、
     抽屉与弹层过渡更连贯、消息淡入上浮；
   - 细节打磨：滚动条美化、输入框聚焦光环、状态点光晕、欢迎页 Logo 高光，
     并尊重系统「减弱动态效果」设置。
3. 版本号升级为 **2.3.4**（versionCode 9）。

### 2.3.3 更新内容

本次修复「备份包含 Termux 环境时，还原失败」的问题。

1. **修复「还原被误判为失败」** ⭐
   解压时若 `tar` 出现 warning（例如无法设置属主、覆盖正在使用的文件），退出码会变成 1；
   旧代码用 `&& echo __ENV_OK__` 串联，warning 一出现就跳过成功标记，于是明明解压成功却报「环境还原失败」。
   现在改为记录 `tar` 的真实退出码，只要环境目录被解压出来就判定成功。
2. **修复「找不到环境包」** ⭐
   还原时 `tarPath` 使用了被备份内容覆盖后的 `backupDir`；若该目录与备份时不同，就会找不到 `.env.tar.gz`。
   现在同时探测「备份内记录的目录 / 当前目录」，并用新增的 `findEnvTar()` 定位。
3. **修复「大环境打包/还原超时」** ⭐
   打包/还原整个环境可能很慢，超时单独放宽到 1 小时（原 10 分钟可能不够），前端等待上限同步放宽。
4. **加固 tar 选择**：优先用内置 `tar`，环境未就绪时回退系统 `toybox tar`；解压统一加
   `--no-same-owner` / `-o`，避免非 root 下因属主问题报错。
5. **错误信息更完整**：备份/还原失败时会回显 `tar` 的完整输出（末尾 300 字符），便于定位。
6. 版本号升级为 **2.3.3**（versionCode 8）。

### 2.3.2 更新内容

1. **修复「用抽帧方式解析视频」完全不可用** ⭐
   以前发视频时自动抽帧总是失败。根因是内置终端给命令设置了 `LD_LIBRARY_PATH`，
   而 Termux 二进制的 RUNPATH 其实已在打包时硬编码，多设这一项反而让 Android linker
   在解析系统库依赖（`/system/lib64/libui.so → libbinder_ndk.so`）时报
   `CANNOT LINK EXECUTABLE`，导致 `ffmpeg` / `ffprobe` 无法运行，抽帧自然失败。
   现已**移除该变量**；实测 `ffmpeg` / `ffprobe` / `python` / `tar` / `pkg` 均恢复正常，
   视频可按时间均匀抽帧成图片交给 AI 观察。同时抽帧失败时会把 ffmpeg 报错回显到消息里，便于排查。

2. **修复「多个复制按钮，点上边的却复制最下边」** ⭐
   代码块渲染时用 `var` 声明的变量被循环内所有「复制」按钮的闭包共享，
   于是每个按钮实际都指向最后一个代码块。现改用 IIFE 固定每次循环的代码块，复制精准对应。

3. **内置终端新增「用户输入」键盘** ⭐
   有些程序（如 `python` 的 `input()`、需要 `y/n` 确认的命令）会等待输入。
   现在终端在命令运行期间会显示一个输入框，输入内容回车即写入该程序的标准输入（stdin），
   用于应对交互式 `input`。为支持这一点，命令的 stdin 不再自动关闭。

4. 版本号升级为 **2.3.2**（versionCode 7）。

### 2.3.1 更新内容

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
LingQiongBuddy-2.3.4/
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
推送后自动构建，产物在本次运行的 **Artifacts** 里（`LingQiongBuddy-2.3.4-debug`）。
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
