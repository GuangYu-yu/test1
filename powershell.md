### 阶段一：配置系统自带的 Windows PowerShell 5.1

这是所有工作的基础，**必须在安装 PowerShell 7 之前完成**，因为后续会直接复用它的配置。

1.  **打开一个普通的 PowerShell 窗口**（无需管理员权限）。

2.  **一键创建并写入配置文件**：复制以下完整命令块，在 PowerShell 中粘贴并回车。它会自动创建 `$PROFILE` 文件并写入最干净的 UTF-8 配置。
<pre><code class="language-powershell">
New-Item -Path (Split-Path $PROFILE) -ItemType Directory -Force | Out-Null
@"
chcp 65001 | Out-Null
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new()
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
`$OutputEncoding = [System.Text.UTF8Encoding]::new()
`$env:PYTHONIOENCODING = "utf-8"
`$env:LANG = "en_US.UTF-8"
`$env:LC_ALL = "en_US.UTF-8"
Set-Location `$env:USERPROFILE
function prompt { `$ESC = [char]27; "`$ESC[36mPS `$(`$executionContext.SessionState.Path.CurrentLocation)`$('>' * (`$nestedPromptLevel + 1))`$ESC[0m " }
"@ | Out-File -FilePath $PROFILE -Encoding utf8 -Force
</code></pre>

3.  **授权运行脚本**：这是让配置自动加载的关键。
    *   在开始菜单找到 “PowerShell”，**右键** → “以管理员身份运行”。
    *   在打开的管理员窗口中，执行：
        ```powershell
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
        ```
    *   提示确认时，输入 `Y` 并回车。

4.  **验证 5.1 配置是否生效**：
    *   关闭所有 PowerShell 窗口。
    *   重新打开一个普通的 PowerShell 窗口（确保是 5.1，可以输入 `$PSVersionTable` 确认）。
    *   检查：提示符是否为蓝色？运行 `$OutputEncoding.EncodingName` 是否显示 `Unicode (UTF-8)`？

---

### 阶段二：安装 PowerShell 7

安装新版不会影响你刚配置好的 5.1，两者会和平共处。

1.  **在任意终端（CMD 或 PowerShell）中**，运行以下命令来安装：
    ```powershell
    winget install --id Microsoft.PowerShell --source winget
    ```
2.  等待安装完成。之后，你可以在任何终端中输入 `pwsh` 来启动 PowerShell 7。

---

### 阶段三：配置 PowerShell 7

PowerShell 7 有自己的独立配置文件，但我们可以**直接复制** 5.1 的配置，无需重写。

1.  **打开 PowerShell 7**（在终端中输入 `pwsh` 并回车，或从开始菜单打开 “PowerShell 7”）。

2.  **从 5.1 复制配置文件到 7**：在 PowerShell 7 窗口中，执行以下命令：
<pre><code class="language-powershell">
New-Item -Path (Split-Path $PROFILE) -ItemType Directory -Force | Out-Null
$oldProfile = "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
if (Test-Path $oldProfile) {
    Copy-Item -Path $oldProfile -Destination $PROFILE -Force
}
</code></pre>

3.  **为 PowerShell 7 单独授权运行脚本**：与 5.1 类似，需要单独设置一次。
    *   在开始菜单找到 “PowerShell 7” 或 “pwsh”，**右键** → “以管理员身份运行”。
    *   在打开的管理员窗口中，执行：
        ```powershell
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
        ```
    *   提示确认时，输入 `Y` 并回车。

4.  **验证 7 的配置是否生效**：
    *   关闭所有 PowerShell 窗口。
    *   重新打开 PowerShell 7（输入 `pwsh` 或从开始菜单打开）。
    *   检查：提示符是否为蓝色？运行 `$OutputEncoding.EncodingName` 是否显示 `Unicode (UTF-8)`？

---

## 📋 流程总结表

| 阶段 | 核心操作 | 关键命令/动作 |
| :--- | :--- | :--- |
| **一：配置 5.1** | 写入 `$PROFILE` + 设置执行策略 | 一键写入命令；`Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| **二：安装 7** | 使用 `winget` 安装 | `winget install --id Microsoft.PowerShell --source winget` |
| **三：配置 7** | 复制 5.1 的配置 + 设置执行策略 | `Copy-Item` 命令；`Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |

---

## 💡 最终状态

*   **Windows PowerShell 5.1**：完美支持 UTF-8，彩色提示符，启动自动加载。
*   **PowerShell 7**：完美支持 UTF-8，彩色提示符，启动自动加载，拥有最新特性。
*   **CMD（可选）**：默认 UTF-8 代码页。