// ============================================================================
//  AppIcon —— 统一取图标（嵌入的 FilterTool.ico，来自原 SteamServerFilter 的图标）
//  嵌入资源可以让托盘拿到精确的 16×16、窗口拿到 32×32，比 ExtractAssociatedIcon 清晰。
// ============================================================================

using System;
using System.Drawing;
using System.Reflection;
using System.Windows.Forms;

namespace SteamServerFilterIpBlock
{
    internal static class AppIcon
    {
        /// <summary>取指定尺寸的应用图标（找不到则退回 exe 自带图标）。</summary>
        public static Icon Load(int size)
        {
            try
            {
                var asm = Assembly.GetExecutingAssembly();
                foreach (var n in asm.GetManifestResourceNames())
                {
                    if (!n.EndsWith(".ico", StringComparison.OrdinalIgnoreCase)) continue;
                    using (var s = asm.GetManifestResourceStream(n))
                        if (s != null) return new Icon(s, new Size(size, size));
                }
            }
            catch { }
            try { return Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch { }
            return SystemIcons.Application;
        }
    }
}
