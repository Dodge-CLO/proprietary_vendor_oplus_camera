#!/usr/bin/env -S PYTHONPATH=../../../../tools/extract-utils python3
#
# SPDX-FileCopyrightText: 2016 The CyanogenMod Project
# SPDX-FileCopyrightText: 2017-2024 The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
#

import os
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import List, NamedTuple, Tuple

from extract_utils.fixups_lib import (
    lib_fixups,
    lib_fixups_user_type,
)
from extract_utils.fixups_blob import (
    blob_fixup,
    blob_fixups_user_type,
)
from extract_utils.main import (
    ExtractUtils,
    ExtractUtilsModule,
)
from extract_utils.tools import (
    apktool_path,
    java_path,
)
from extract_utils.utils import Color, color_print, run_cmd

def lib_fixup_system_ext_suffix(lib: str, partition: str, *args, **kwargs):
    if partition != 'system_ext':
        return None

    system_ext_libs = {
        'libSuperTextWrapper',
        'libXDocProcessSDK',
        'libYTCommon',
        'libmpbase',
        'libextendfile',
    }

    return f'{lib}_system_ext' if lib in system_ext_libs else None

lib_fixups: lib_fixups_user_type = {
    **lib_fixups,
    (
        'libSuperTextWrapper',
        'libXDocProcessSDK',
        'libYTCommon',
        'libmpbase',
        'libextendfile',
    ): lib_fixup_system_ext_suffix,
}

def blob_fixup_opluscamera_privapp_linker_ns(
    ctx, file, file_path, *args, tmp_dir=None, **kwargs
):
    """
    Keep OplusCamera on the system_ext priv-app linker path that can resolve
    libvndksupport for libJniMetaTransform (capture APS meta path).

    When OplusCamera gets installed as an update under /data/app, its JNI
    libs are extracted to lib/arm64/ and the app classloader namespace can't
    see /system/lib64/libvndksupport.so, so still capture throws
    UnsatisfiedLinkError. Loading from the system_ext priv-app APK goes
    through the shared namespace and works.

    Hardening applied on every extract:
      1) android:extractNativeLibs="false" so PackageManager loads the libs
         straight from the APK.
      2) Drop android.permission.CONTROL_KEYGUARD. PackageManager refuses
         uninstall-system-updates for packages holding it, which traps an
         accidental adb-installed update in the broken /data state. The
         secure camera still works through showWhenLocked and
         SUBSCRIBE_TO_KEYGUARD_LOCKED_STATE.
    """
    if tmp_dir is None:
        return

    manifest = Path(tmp_dir) / 'AndroidManifest.xml'
    if not manifest.exists():
        print('OplusCamera: warning: AndroidManifest.xml missing for linker-ns fixup')
        return

    data = manifest.read_text(encoding='utf-8')
    original = data
    changed = []

    # Force extractNativeLibs=false on <application ...>
    if re.search(r'android:extractNativeLibs\s*=\s*"true"', data):
        data = re.sub(
            r'android:extractNativeLibs\s*=\s*"true"',
            'android:extractNativeLibs="false"',
            data,
            count=1,
        )
        changed.append('extractNativeLibs=false')
    elif 'android:extractNativeLibs=' not in data:
        # Insert on the application tag (first match).
        new_data, n = re.subn(
            r'(<application\b)(\s)',
            r'\1 android:extractNativeLibs="false"\2',
            data,
            count=1,
        )
        if n:
            data = new_data
            changed.append('extractNativeLibs=false (inserted)')
    # else already false, leave it alone

    # Remove the CONTROL_KEYGUARD uses-permission (self-closing or paired).
    perm_re = re.compile(
        r'[ \t]*<uses-permission\b[^>]*android:name\s*=\s*'
        r'"android\.permission\.CONTROL_KEYGUARD"[^>]*/>\s*\n?'
        r'|[ \t]*<uses-permission\b[^>]*android:name\s*=\s*'
        r'"android\.permission\.CONTROL_KEYGUARD"[^>]*>\s*'
        r'</uses-permission>\s*\n?',
        re.MULTILINE,
    )
    data2, n = perm_re.subn('', data)
    if n:
        data = data2
        changed.append(f'removed CONTROL_KEYGUARD (x{n})')

    if data != original:
        manifest.write_text(data, encoding='utf-8')
        print('OplusCamera: priv-app linker ns fixup: ' + ', '.join(changed))
    else:
        print('OplusCamera: priv-app linker ns fixup already applied')

# Every patch asserts a marker in the decoded tree before it is packed.

VERIFY_RESULTS: List[Tuple[str, str, bool]] = []

class Check(NamedTuple):
    what: str
    needle: str
    # Basename glob (searched recursively) or a concrete path under tmp_dir.
    where: str = '*.smali'
    present: bool = True

def _check_hit(root: Path, chk: Check) -> bool:
    # Concrete path, utf-16 fallback for binary AXML.
    if '*' not in chk.where and '?' not in chk.where:
        target = root / chk.where
        if not target.is_file():
            return False
        raw = target.read_bytes()
        return (
            chk.needle.encode() in raw or chk.needle.encode('utf-16-le') in raw
        )

    try:
        out = run_cmd([
            'grep',
            '-rlaF',
            '--include',
            chk.where,
            '-e',
            chk.needle,
            str(root),
        ])
    except ValueError:
        return False  # grep exits 1 when nothing matches

    return bool(out.strip())

def verify(label: str, *checks: Check):
    def impl(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
        if tmp_dir is None:
            return
        root = Path(tmp_dir)
        for chk in checks:
            ok = _check_hit(root, chk) == chk.present
            # A missing file can't prove a removal.
            concrete = '*' not in chk.where and '?' not in chk.where
            if not chk.present and concrete and not (root / chk.where).is_file():
                ok = False
            VERIFY_RESULTS.append((label, chk.what, ok))

    return impl

OPLUSCAMERA_CHECKS = (
    # patches/0001: TypeFaceUtil.a() no longer uses OplusBaseConfiguration.
    Check(
        '0001 default font',
        'Landroid/content/res/OplusBaseConfiguration;',
        'smali/pa/n3.smali',
        False,
    ),
    # patches/0002: the oplus-only android:permission attributes are removed.
    Check(
        '0002 oplus perms stripped',
        'android:permission="oplus.permission.OPLUS_COMPONENT_SAFE"',
        'AndroidManifest.xml',
        False,
    ),
    Check(
        '0002 oplus safe perms stripped',
        'android:permission="com.oplus.permission.safe.KEY_EVENT"',
        'AndroidManifest.xml',
        False,
    ),
    # blob_fixup_opluscamera_privapp_linker_ns
    Check(
        'linker-ns extractNativeLibs=false',
        'android:extractNativeLibs="false"',
        'AndroidManifest.xml',
    ),
    Check(
        'linker-ns CONTROL_KEYGUARD dropped',
        'android.permission.CONTROL_KEYGUARD',
        'AndroidManifest.xml',
        False,
    ),
)

SDK_CHECKS = (
    # patches-sdk/0001: the explicit static initializers are dropped.
    Check(
        '0001 fixes',
        '.field private static bInit:Z = false',
        'smali/com/oplus/ocs/camera/common/parameter/apsadapter/ApsHelper.smali',
        False,
    ),
    # patches-sdk/0002: the camera lib dir falls back to system_ext.
    Check(
        '0002 system_ext lib dir',
        '"/system_ext/lib64"',
        'smali/com/oplus/ocs/camera/consumer/apsAdapter/adapter/ApsUtils.smali',
    ),
    Check(
        '0002 product lib dir gone',
        '"/product/lib64"',
        'smali/com/oplus/ocs/camera/consumer/apsAdapter/adapter/ApsUtils.smali',
        False,
    ),
)

def _replace_smali_method(data: str, signature: str, body: str) -> str:
    return re.sub(
        rf'(?ms)^\.method {re.escape(signature)}\n.*?^\.end method',
        f'.method {signature}\n{body}.end method',
        data,
        count=1,
    )


def _smali_method(data: str, signature: str):
    return re.search(
        rf'(?ms)^(\.method[^\n]* {re.escape(signature)}\n)(.*?)(^\.end method)',
        data,
    )


def blob_fixup_apktool_unpack_src(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    if tmp_dir is None:
        return

    run_cmd([
        java_path,
        '-Xmx8g',
        '-jar',
        apktool_path,
        'd',
        file_path,
        '-o',
        tmp_dir,
        '-f',
        '--no-res',
    ])


def blob_fixup_aiunit_baseos_empty(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # Avoid ClassNotFoundException for com.oplus.cust.OplusCfgFilePolicy on non-OOS.
    if tmp_dir is None:
        return

    smali = Path(tmp_dir) / (
        'smali_classes2/com/oplus/aiunit/configuration/data/assets/'
        'BaseOSLoadStrategy.smali'
    )
    if not smali.exists():
        return

    body = (
        '    .locals 1\n'
        '\n'
        '    invoke-static {}, Ljava/util/Collections;->emptyMap()Ljava/util/Map;\n'
        '\n'
        '    move-result-object v0\n'
        '\n'
        '    return-object v0\n'
    )
    data = smali.read_text(encoding='utf-8')
    fixed = _replace_smali_method(
        data,
        'public final listFilesFromOS(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Ljava/util/Map;',
        body,
    )
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')


def blob_fixup_aiunit_authorize_camera(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # Whitelist com.oplus.camera + com.oneplus.gallery for AIUnit authorize().
    if tmp_dir is None:
        return

    smali = Path(tmp_dir) / 'smali_classes2/com/oplus/aiunit/core/AIUnitServiceBinder.smali'
    if not smali.exists():
        return

    data = smali.read_text(encoding='utf-8')
    old = (
        '    :goto_2\n'
        '    new-instance v10, Ljava/lang/StringBuilder;\n'
    )
    new = (
        '    :goto_2\n'
        '    const-string v10, "com.oplus.camera"\n'
        '\n'
        '    invoke-static {v5, v10}, Lkotlin/jvm/internal/Intrinsics;->areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z\n'
        '\n'
        '    move-result v10\n'
        '\n'
        '    if-nez v10, :cond_oplus_aiunit_trusted_auth\n'
        '\n'
        '    const-string v10, "com.oneplus.gallery"\n'
        '\n'
        '    invoke-static {v5, v10}, Lkotlin/jvm/internal/Intrinsics;->areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z\n'
        '\n'
        '    move-result v10\n'
        '\n'
        '    if-eqz v10, :cond_oplus_aiunit_auth\n'
        '\n'
        '    :cond_oplus_aiunit_trusted_auth\n'
        '    const/4 v9, 0x1\n'
        '\n'
        '    :cond_oplus_aiunit_auth\n'
        '    new-instance v10, Ljava/lang/StringBuilder;\n'
    )
    marker = '    const-string v12, "authorize "\n'
    idx = data.find(marker)
    if idx < 0:
        return
    chunk_start = data.rfind(old, 0, idx)
    if chunk_start < 0:
        return
    fixed = data[:chunk_start] + new + data[chunk_start + len(old) :]
    if fixed != data:
        smali.write_text(fixed, encoding='utf-8')

    provider = Path(tmp_dir) / 'smali_classes2/com/oplus/aiunit/AIUnitProvider.smali'
    if not provider.exists():
        return
    pdata = provider.read_text(encoding='utf-8')
    m = re.search(r'(?ms)^\.method public final e\(\)Z\n.*?^\.end method', pdata)
    if not m:
        return
    method = m.group(0)
    pold = (
        '    :cond_0\n'
        '    invoke-virtual {p0}, Lcom/oplus/aiunit/base/component/BaseContentProvider;->a()Landroid/content/Context;\n'
    )
    pnew = (
        '    :cond_0\n'
        '    const-string v1, "com.oplus.camera"\n'
        '\n'
        '    invoke-static {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z\n'
        '\n'
        '    move-result v1\n'
        '\n'
        '    if-nez v1, :cond_oplus_aiunit_provider_trusted\n'
        '\n'
        '    const-string v1, "com.oneplus.gallery"\n'
        '\n'
        '    invoke-static {v0, v1}, Lkotlin/jvm/internal/Intrinsics;->areEqual(Ljava/lang/Object;Ljava/lang/Object;)Z\n'
        '\n'
        '    move-result v1\n'
        '\n'
        '    if-eqz v1, :cond_oplus_aiunit_provider_check\n'
        '\n'
        '    :cond_oplus_aiunit_provider_trusted\n'
        '    const/4 p0, 0x1\n'
        '\n'
        '    return p0\n'
        '\n'
        '    :cond_oplus_aiunit_provider_check\n'
        '    invoke-virtual {p0}, Lcom/oplus/aiunit/base/component/BaseContentProvider;->a()Landroid/content/Context;\n'
    )
    if pold not in method:
        return
    method2 = method.replace(pold, pnew, 1)
    provider.write_text(pdata[: m.start()] + method2 + pdata[m.end() :], encoding='utf-8')


def blob_fixup_aiunit_plugin_so_permissions(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # Make the libs AIUnit unpacks executable, or dlopen fails.
    if tmp_dir is None:
        return

    smali = Path(tmp_dir) / 'smali_classes2/com/oplus/orange/utils/FileUtil.smali'
    if not smali.exists():
        return
    data = smali.read_text(encoding='utf-8')

    # 1) unzipSoFromPlugin
    old_plugin = (
        '    invoke-static {v2, v9, v10}, Lcom/oplus/orange/utils/FileUtil;->unzip(Ljava/util/zip/ZipFile;Ljava/util/zip/ZipEntry;Ljava/io/File;)V\n'
        '\n'
        '    .line 218\n'
        '    .line 219\n'
        '    .line 220\n'
        '    const/4 v9, 0x0\n'
    )
    new_plugin = (
        '    invoke-static {v2, v9, v10}, Lcom/oplus/orange/utils/FileUtil;->unzip(Ljava/util/zip/ZipFile;Ljava/util/zip/ZipEntry;Ljava/io/File;)V\n'
        '\n'
        '    const/4 v9, 0x1\n'
        '\n'
        '    invoke-virtual {v10, v9}, Ljava/io/File;->setReadable(Z)Z\n'
        '\n'
        '    invoke-virtual {v10, v9}, Ljava/io/File;->setExecutable(Z)Z\n'
        '\n'
        '    .line 218\n'
        '    .line 219\n'
        '    .line 220\n'
        '    const/4 v9, 0x0\n'
    )
    if old_plugin in data:
        data = data.replace(old_plugin, new_plugin, 1)

    # 2) private unzip(): p2 is clobbered, stash it in v2.
    old_priv = (
        '.method private static final unzip(Ljava/util/zip/ZipFile;Ljava/util/zip/ZipEntry;Ljava/io/File;)V\n'
        '    .registers 5\n'
    )
    new_priv = (
        '.method private static final unzip(Ljava/util/zip/ZipFile;Ljava/util/zip/ZipEntry;Ljava/io/File;)V\n'
        '    .registers 6\n'
    )
    if old_priv in data:
        data = data.replace(old_priv, new_priv, 1)
    if 'move-object v2, p2' not in data:
        old_stash = (
            '    :cond_28\n'
            '    invoke-virtual {p0, p1}, Ljava/util/zip/ZipFile;->getInputStream(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;\n'
        )
        new_stash = (
            '    :cond_28\n'
            '    move-object v2, p2\n'
            '\n'
            '    invoke-virtual {p0, p1}, Ljava/util/zip/ZipFile;->getInputStream(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;\n'
        )
        if old_stash in data:
            data = data.replace(old_stash, new_stash, 1)
    if 'invoke-virtual {v2, v0}, Ljava/io/File;->setExecutable' not in data:
        old_ret = (
            '    invoke-static {p0, v1}, Lkotlin/io/CloseableKt;->closeFinally(Ljava/io/Closeable;Ljava/lang/Throwable;)V\n'
            '\n'
            '    .line 63\n'
            '    .line 64\n'
            '    .line 65\n'
            '    return-void\n'
            '\n'
            '    .line 66\n'
            '    :catchall_41\n'
        )
        new_ret = (
            '    invoke-static {p0, v1}, Lkotlin/io/CloseableKt;->closeFinally(Ljava/io/Closeable;Ljava/lang/Throwable;)V\n'
            '\n'
            '    const/4 v0, 0x1\n'
            '\n'
            '    invoke-virtual {v2, v0}, Ljava/io/File;->setReadable(Z)Z\n'
            '\n'
            '    invoke-virtual {v2, v0}, Ljava/io/File;->setExecutable(Z)Z\n'
            '\n'
            '    .line 63\n'
            '    .line 64\n'
            '    .line 65\n'
            '    return-void\n'
            '\n'
            '    .line 66\n'
            '    :catchall_41\n'
        )
        if old_ret in data:
            data = data.replace(old_ret, new_ret, 1)

    # 3) copyFile(): p1 is clobbered, stash it in v5.
    old_copy_open = (
        '    invoke-direct {p2, p1}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V\n'
        '    :try_end_6b\n'
        '    .catch Ljava/io/IOException; {:try_start_f .. :try_end_6b} :catch_52\n'
        '\n'
        '    .line 106\n'
        '    .line 107\n'
        '    .line 108\n'
        '    const/16 p1, 0x2000\n'
    )
    new_copy_open = (
        '    invoke-direct {p2, p1}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V\n'
        '    :try_end_6b\n'
        '    .catch Ljava/io/IOException; {:try_start_f .. :try_end_6b} :catch_52\n'
        '\n'
        '    move-object v5, p1\n'
        '\n'
        '    .line 106\n'
        '    .line 107\n'
        '    .line 108\n'
        '    const/16 p1, 0x2000\n'
    )
    old_copy_ret = (
        '    :cond_7c\n'
        '    const/4 p0, 0x0\n'
        '\n'
        '    .line 126\n'
        '    :try_start_7d\n'
        '    invoke-static {p2, p0}, Lkotlin/io/CloseableKt;->closeFinally(Ljava/io/Closeable;Ljava/lang/Throwable;)V\n'
        '    :try_end_80\n'
        '    .catch Ljava/io/IOException; {:try_start_7d .. :try_end_80} :catch_52\n'
        '\n'
        '    .line 127\n'
        '    .line 128\n'
        '    .line 129\n'
        '    return v4\n'
    )
    new_copy_ret = (
        '    :cond_7c\n'
        '    const/4 p0, 0x0\n'
        '\n'
        '    .line 126\n'
        '    :try_start_7d\n'
        '    invoke-static {p2, p0}, Lkotlin/io/CloseableKt;->closeFinally(Ljava/io/Closeable;Ljava/lang/Throwable;)V\n'
        '    :try_end_80\n'
        '    .catch Ljava/io/IOException; {:try_start_7d .. :try_end_80} :catch_52\n'
        '\n'
        '    new-instance p0, Ljava/io/File;\n'
        '\n'
        '    invoke-direct {p0, v5}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n'
        '\n'
        '    const/4 p1, 0x1\n'
        '\n'
        '    invoke-virtual {p0, p1}, Ljava/io/File;->setReadable(Z)Z\n'
        '\n'
        '    invoke-virtual {p0, p1}, Ljava/io/File;->setExecutable(Z)Z\n'
        '\n'
        '    .line 127\n'
        '    .line 128\n'
        '    .line 129\n'
        '    return v4\n'
    )
    if old_copy_open in data and old_copy_ret in data:
        data = data.replace(old_copy_open, new_copy_open, 1).replace(
            old_copy_ret, new_copy_ret, 1
        )

    smali.write_text(data, encoding='utf-8')

    # 4) AbsInstaller.unzipMatchedEntryIfNeeded
    abs_smali = Path(tmp_dir) / 'smali_classes2/com/oplus/orange/install/AbsInstaller.smali'
    if abs_smali.exists():
        adata = abs_smali.read_text(encoding='utf-8')
        if 'setExecutable' not in adata:
            old_abs = (
                '    :cond_54\n'
                '    new-instance p2, Ljava/io/FileOutputStream;\n'
                '\n'
                '    .line 86\n'
                '    .line 87\n'
                '    invoke-direct {p2, p0}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V\n'
                '\n'
                '    .line 88\n'
                '    .line 89\n'
                '    .line 90\n'
                '    const/4 p0, 0x0\n'
            )
            new_abs = (
                '    :cond_54\n'
                '    move-object v0, p0\n'
                '\n'
                '    new-instance p2, Ljava/io/FileOutputStream;\n'
                '\n'
                '    .line 86\n'
                '    .line 87\n'
                '    invoke-direct {p2, p0}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V\n'
                '\n'
                '    .line 88\n'
                '    .line 89\n'
                '    .line 90\n'
                '    const/4 p0, 0x0\n'
            )
            old_abs_ret = (
                '    invoke-static {p2, p4}, Lkotlin/io/CloseableKt;->closeFinally(Ljava/io/Closeable;Ljava/lang/Throwable;)V\n'
                '\n'
                '    .line 97\n'
                '    .line 98\n'
                '    .line 99\n'
                '    goto :goto_6a\n'
            )
            new_abs_ret = (
                '    invoke-static {p2, p4}, Lkotlin/io/CloseableKt;->closeFinally(Ljava/io/Closeable;Ljava/lang/Throwable;)V\n'
                '\n'
                '    const/4 p1, 0x1\n'
                '\n'
                '    invoke-virtual {v0, p1}, Ljava/io/File;->setReadable(Z)Z\n'
                '\n'
                '    invoke-virtual {v0, p1}, Ljava/io/File;->setExecutable(Z)Z\n'
                '\n'
                '    .line 97\n'
                '    .line 98\n'
                '    .line 99\n'
                '    goto :goto_6a\n'
            )
            if old_abs in adata and old_abs_ret in adata:
                adata = adata.replace(old_abs, new_abs, 1).replace(old_abs_ret, new_abs_ret, 1)
                abs_smali.write_text(adata, encoding='utf-8')


def blob_fixup_aiunit_si_preference_roots(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    """Google SI requires root <PreferenceScreen>, not androidx.preference.PreferenceScreen.

    AIUnit ships COUI preference XMLs with the androidx root. That is fine for
    Oplus Settings, but Settings Intelligence hard-crashes while indexing:
      XML document must start with <PreferenceScreen> tag; found
      androidx.preference.PreferenceScreen ... fragment_ai_service_platform
    Camera/Gallery AI paths do not use these XMLs. Only rewrite when res/xml is
    present (full apktool decode); --no-res extracts skip this safely.
    """
    if tmp_dir is None:
        return
    xml_dir = Path(tmp_dir) / 'res' / 'xml'
    if not xml_dir.is_dir():
        return
    changed = 0
    for path in xml_dir.glob('fragment*.xml'):
        data = path.read_text(encoding='utf-8')
        new = data.replace(
            '<androidx.preference.PreferenceScreen', '<PreferenceScreen'
        ).replace(
            '</androidx.preference.PreferenceScreen>', '</PreferenceScreen>'
        )
        if new != data:
            path.write_text(new, encoding='utf-8')
            changed += 1
    if changed:
        print(f'AIUnit: fixed PreferenceScreen root on {changed} fragment XML(s)')


def _aiunit_patch_settings_manifest_text(data: str) -> str:
    """Strip Settings search injection from a decoded AndroidManifest.xml."""
    original = data
    # Remove search / settings-switch providers entirely (order-independent).
    data = re.sub(
        r'\s*<provider\b[^>]*?(?:'
        r'android:authorities="com\.oplus\.aiunit\.search"'
        r'|android:authorities="com\.oplus\.aiunit\.authority\.settings\.switch"'
        r'|android:name="com\.oplus\.aiunit\.settings\.search\.AIUnitSearchIndexProvider"'
        r'|android:name="[^"]*AIUnitSettingsSwitchProvider"'
        r')[^>]*?(?:/>|>[\s\S]*?</provider>)',
        '',
        data,
        flags=re.IGNORECASE,
    )
    data = data.replace(
        'android:name="ai::meta::enable_settings_ui" android:value="true"',
        'android:name="ai::meta::enable_settings_ui" android:value="false"',
    )
    data = data.replace(
        'android:name="ai::meta::enable_local_llm_settings_ui" android:value="true"',
        'android:name="ai::meta::enable_local_llm_settings_ui" android:value="false"',
    )
    # De-export manufacturer settings activities so they are not IA_SETTINGS tiles.
    for act in (
        'com.oplus.aiunit.settings.AIUnitSettingsActivity',
        'com.oplus.aiunit.settings.ExpAIStrengthenActivity',
    ):
        data = re.sub(
            rf'(<activity\b[^>]*android:name="{re.escape(act)}"[^>]*?)'
            r'android:exported="true"',
            r'\1android:exported="false"',
            data,
        )
    if data != original:
        print('AIUnit: stripped Settings search/index injection from text manifest')
    return data


def blob_fixup_aiunit_disable_settings(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    """Keep AIUnit for Camera/Gallery; do not inject into system Settings / SI."""
    if tmp_dir is None:
        return

    manifest = Path(tmp_dir) / 'AndroidManifest.xml'
    original_manifest = Path(tmp_dir) / 'original' / 'AndroidManifest.xml'

    # 1) Decoded text manifest (apktool d, with or without --no-res).
    if manifest.exists() and manifest.read_bytes()[:1] == b'<':
        data = manifest.read_text(encoding='utf-8')
        new = _aiunit_patch_settings_manifest_text(data)
        if new != data:
            manifest.write_text(new, encoding='utf-8')
        return

    # 2) Optional binary AXML path when only original/ has the binary.
    try:
        import pyaxml
    except ImportError:
        print('AIUnit: pyaxml unavailable and no text manifest; settings strip skipped')
        return

    target = None
    for c in (manifest, original_manifest):
        if c.exists() and c.stat().st_size > 0:
            head = c.read_bytes()[:4]
            if head[:2] == b'\x03\x00' or head == b'\x03\x00\x08\x00' or (
                head and head[0] != ord('<')
            ):
                target = c
                break
    if target is None:
        return

    axml = pyaxml.AXML.from_axml(target.read_bytes())
    root = axml.to_xml()
    NS = '{http://schemas.android.com/apk/res/android}'

    def get_a(el, name):
        for k, v in el.attrib.items():
            if k == name or k.endswith('}' + name) or k.endswith(':' + name):
                return v
        return None

    def set_a(el, name, value):
        for k in list(el.attrib):
            if k == name or k.endswith('}' + name) or k.endswith(':' + name):
                el.attrib[k] = value
                return
        el.attrib[NS + name] = value

    app = next(e for e in root.iter() if e.tag.split('}')[-1] == 'application')
    for prov in list(app):
        if prov.tag.split('}')[-1] != 'provider':
            continue
        auth = get_a(prov, 'authorities') or ''
        name = get_a(prov, 'name') or ''
        # OplusSearchIndexablesProvider requires exported, drop it.
        if auth in (
            'com.oplus.aiunit.search',
            'com.oplus.aiunit.authority.settings.switch',
        ) or 'AIUnitSearchIndexProvider' in name or 'AIUnitSettingsSwitchProvider' in name:
            app.remove(prov)
    for meta in [e for e in app if e.tag.split('}')[-1] == 'meta-data']:
        name = get_a(meta, 'name') or ''
        if name in (
            'ai::meta::enable_settings_ui',
            'ai::meta::enable_local_llm_settings_ui',
        ):
            set_a(meta, 'value', 'false')
    for act in [e for e in app if e.tag.split('}')[-1] == 'activity']:
        name = get_a(act, 'name') or ''
        if name not in (
            'com.oplus.aiunit.settings.AIUnitSettingsActivity',
            'com.oplus.aiunit.settings.ExpAIStrengthenActivity',
        ):
            continue
        set_a(act, 'exported', 'false')
        for child in list(act):
            tag = child.tag.split('}')[-1]
            if tag == 'intent-filter':
                blob = ' '.join(
                    filter(None, (get_a(sub, 'name') for sub in child.iter()))
                )
                if 'MANUFACTURER_APPLICATION_SETTING' in blob:
                    act.remove(child)
            elif tag == 'meta-data':
                mname = get_a(child, 'name') or ''
                if mname.startswith('com.android.settings.') or mname.startswith(
                    'com.oplus.settings.'
                ):
                    act.remove(child)
    new = pyaxml.AXML()
    new.from_xml(root)
    target.write_bytes(new.pack())
    print('AIUnit: stripped Settings search/index injection from binary manifest')


def blob_fixup_aon_disable_ezpay_settings(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    """Keep AON camera AI; strip EZ Pay Settings injection (Intelligent Perception)."""
    if tmp_dir is None:
        return
    try:
        import pyaxml
    except ImportError:
        return

    candidates = [
        Path(tmp_dir) / 'AndroidManifest.xml',
        Path(tmp_dir) / 'original' / 'AndroidManifest.xml',
    ]
    target = None
    for c in candidates:
        if c.exists() and c.stat().st_size > 0:
            head = c.read_bytes()[:4]
            if head[:2] == b'\x03\x00' or head == b'\x03\x00\x08\x00' or head[0] != ord('<'):
                target = c
                break
    if target is None:
        manifest = Path(tmp_dir) / 'AndroidManifest.xml'
        if manifest.exists() and manifest.read_text(encoding='utf-8', errors='ignore').lstrip().startswith('<'):
            data = manifest.read_text(encoding='utf-8')
            # Drop Settings injection action; keep AON runtime.
            data = data.replace(
                '<action android:name="com.android.settings.MANUFACTURER_APPLICATION_SETTING"/>',
                '',
            )
            data = re.sub(
                r'<provider\b[^>]*IntelligentSearchIndexablesProvider[\s\S]*?</provider>',
                '',
                data,
                count=1,
            )
            manifest.write_text(data, encoding='utf-8')
        return

    axml = pyaxml.AXML.from_axml(target.read_bytes())
    root = axml.to_xml()
    NS = '{http://schemas.android.com/apk/res/android}'

    def get_a(el, name):
        for k, v in el.attrib.items():
            if k == name or k.endswith('}' + name) or k.endswith(':' + name):
                return v
        return None

    def set_a(el, name, value):
        for k in list(el.attrib):
            if k == name or k.endswith('}' + name) or k.endswith(':' + name):
                el.attrib[k] = value
                return
        el.attrib[NS + name] = value

    app = next(e for e in root.iter() if e.tag.split('}')[-1] == 'application')
    for prov in list(app):
        if prov.tag.split('}')[-1] != 'provider':
            continue
        name = get_a(prov, 'name') or ''
        if 'IntelligentSearchIndexablesProvider' in name:
            app.remove(prov)
    for act in [e for e in app if e.tag.split('}')[-1] == 'activity']:
        name = get_a(act, 'name') or ''
        if 'IntelligentPerceptionActivity' not in name:
            continue
        set_a(act, 'exported', 'false')
        for child in list(act):
            tag = child.tag.split('}')[-1]
            if tag == 'intent-filter':
                blob = ' '.join(
                    filter(None, (get_a(sub, 'name') for sub in child.iter()))
                )
                if 'MANUFACTURER_APPLICATION_SETTING' in blob:
                    act.remove(child)
            elif tag == 'meta-data':
                mname = get_a(child, 'name') or ''
                if mname.startswith('com.android.settings.') or mname.startswith(
                    'com.oplus.settings.'
                ):
                    act.remove(child)
    new = pyaxml.AXML()
    new.from_xml(root)
    target.write_bytes(new.pack())


def blob_fixup_stdid_receiver_flags(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # A14+ requires RECEIVER_EXPORTED / RECEIVER_NOT_EXPORTED.
    if tmp_dir is None:
        return

    smali = Path(tmp_dir) / 'smali/com/oplus/stdid/AppApplication.smali'
    if not smali.exists():
        return

    new_method = '''.method public final onCreate()V
    .locals 7

    invoke-super {p0}, Landroid/app/Application;->onCreate()V

    sget-object v0, Lq0/b;->b:Lq0/b;

    const/4 v6, 0x0

    if-nez v0, :cond_0

    new-instance v0, Lq0/b;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v6, v0, Lq0/b;->a:Ljava/lang/String;

    sput-object v0, Lq0/b;->b:Lq0/b;

    :cond_0
    sget-object v0, Lq0/b;->b:Lq0/b;

    invoke-virtual {v0, p0}, Lq0/b;->a(Landroid/content/Context;)V

    new-instance v2, Landroid/content/IntentFilter;

    invoke-direct {v2}, Landroid/content/IntentFilter;-><init>()V

    const-string v0, "oplus.intent.action.PACKAGE_REMOVED"

    invoke-virtual {v2, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    const-string v0, "package"

    invoke-virtual {v2, v0}, Landroid/content/IntentFilter;->addDataScheme(Ljava/lang/String;)V

    const-string v3, "oplus.permission.OPLUS_COMPONENT_SAFE"

    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    iget-object v1, p0, Lcom/oplus/stdid/AppApplication;->a:Lp0/a;

    const/4 v5, 0x4

    if-eqz v0, :cond_1

    invoke-virtual {p0, v1, v2, v5}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)Landroid/content/Intent;

    goto :goto_0

    :cond_1
    move-object v0, p0
    move-object v4, v6
    invoke-virtual/range {v0 .. v5}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;I)Landroid/content/Intent;

    :goto_0
    return-void
.end method
'''
    data = smali.read_text(encoding='utf-8')
    fixed, n = re.subn(
        r'(?ms)^\.method public final onCreate\(\)V\n.*?^\.end method',
        new_method,
        data,
        count=1,
    )
    if n:
        smali.write_text(fixed, encoding='utf-8')


GALLERY_X8_SIGNATURE = '.method public final x8(Ljava/lang/String;Z)Ljava/lang/Boolean;'
GALLERY_OLIVE_DONE_ANCHOR = '    :goto_olive_done\n'

# Off OOS no AppFeature provider answers, so these read false.
GALLERY_FORCED_FLAGS = (
    # ProXDR badge
    'feature_is_support_local_hdr',
    'feature_is_support_ultra_hdr',
    # 10-bit decode
    'feature_is_support_10bit_decode',
    # Badge gate, not the View with ProXDR toggle
    'local_hdr_switch_read',
    # Use Display.getHdrSdrRatio() instead of the ColorOS listener
    'feature_is_support_edr_listener',
)


def blob_fixup_gallery_force_flags(ctx, file, file_path, *args, tmp_dir=None, **kwargs):
    # Extend the keys patches-gallery/0004 forces on.
    if tmp_dir is None:
        return

    root = Path(tmp_dir)
    smali = None
    for candidate in sorted(root.glob('smali*/com/oplus/**/*.smali')):
        if GALLERY_OLIVE_DONE_ANCHOR in candidate.read_text(encoding='utf-8'):
            smali = candidate
            break
    if smali is None:
        raise RuntimeError(
            'gallery: the 0004 olive anchor is missing, so the feature flags '
            'cannot be forced. patches-gallery/0004 has probably stopped '
            'applying against this blob.'
        )

    data = smali.read_text(encoding='utf-8')
    if 'cond_force_10bit_true' in data:
        return

    chain = ''
    for flag in GALLERY_FORCED_FLAGS:
        chain += (
            f'    const-string v0, "{flag}"\n'
            '\n'
            '    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n'
            '\n'
            '    move-result v1\n'
            '\n'
            '    if-nez v1, :cond_force_10bit_true\n'
            '\n'
        )

    # Reuses v0/v1 like 0004.
    inject = (
        chain
        + '    goto :goto_force_10bit_done\n'
        '\n'
        '    :cond_force_10bit_true\n'
        '    const/4 v0, 0x1\n'
        '\n'
        '    return v0\n'
        '\n'
        '    :goto_force_10bit_done\n'
        '\n'
    )

    smali.write_text(
        data.replace(
            GALLERY_OLIVE_DONE_ANCHOR, GALLERY_OLIVE_DONE_ANCHOR + '\n' + inject, 1
        ),
        encoding='utf-8',
    )

    # Same flags on the ConfigAbility getter x8(String, boolean).
    getter = None
    for candidate in sorted(
        root.glob('smali*/com/oplus/gallery/framework/abilities/config/*.smali')
    ):
        text = candidate.read_text(encoding='utf-8')
        if GALLERY_X8_SIGNATURE in text:
            getter = candidate
            break
    if getter is None:
        raise RuntimeError(
            'gallery: the ConfigAbility boolean getter x8(String, boolean) is '
            'missing, so the HDR flags cannot be forced on its path.'
        )

    text = getter.read_text(encoding='utf-8')
    if 'cond_force_x8_true' in text:
        return

    chain = ''
    for flag in GALLERY_FORCED_FLAGS:
        chain += (
            f'    const-string v0, "{flag}"\n'
            '\n'
            '    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z\n'
            '\n'
            '    move-result v1\n'
            '\n'
            '    if-nez v1, :cond_force_x8_true\n'
            '\n'
        )
    inject = (
        chain
        + '    goto :goto_force_x8_done\n'
        '\n'
        '    :cond_force_x8_true\n'
        '    const/4 v0, 0x1\n'
        '\n'
        '    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;\n'
        '\n'
        '    move-result-object v0\n'
        '\n'
        '    return-object v0\n'
        '\n'
        '    :goto_force_x8_done\n'
        '\n'
    )
    head = GALLERY_X8_SIGNATURE + '\n    .locals 2\n'
    if head not in text:
        raise RuntimeError(
            'gallery: ConfigAbility x8 no longer starts with .locals 2; the '
            'forced-flag injection needs to be redone for this blob.'
        )
    getter.write_text(text.replace(head, head + '\n' + inject, 1), encoding='utf-8')


GALLERY_CHECKS = (
    # patches-gallery/0001: oppo-only android:permission attributes removed.
    Check(
        '0001 oppo perms stripped',
        'android:permission="oppo.permission.OPPO_COMPONENT_SAFE"',
        'AndroidManifest.xml',
        False,
    ),
    # patches-gallery/0002: RECEIVER_NOT_EXPORTED injection label.
    Check('0002 RECEIVER_NOT_EXPORTED', ':cond_no_or'),
    # patches-gallery/0003: PhotoEditor_Theme.Hassel items.
    Check(
        '0003 PhotoEditor theme items',
        '@color/action_bar_done_text_color_pressed_hassel</item>\n'
        '        <item name="de_toolkit_undo_drawable_m">',
        'res/values/styles.xml',
    ),
    # patches-gallery/0004: Olive keys forced on in ConfigAbilityWrapper.
    Check(
        '0004 live photos',
        ':cond_olive_enabled',
        'smali/com/oplus/aiunit/vision/e7b.smali',
    ),
    # blob_fixup_gallery_force_flags: 10-bit decode forced on.
    Check(
        'HDR viewer and 10-bit decode flags forced',
        ':cond_force_10bit_true',
        'smali/com/oplus/aiunit/vision/e7b.smali',
    ),
    Check(
        'HDR flags forced on the ConfigAbility getter',
        ':cond_force_x8_true',
        'smali_classes2/com/oplus/gallery/framework/abilities/config/a.smali',
    ),
)

AIUNIT_CHECKS = (
    Check(
        'SearchIndexablesProvider stripped',
        'OplusSearchIndexablesProvider',
        'AndroidManifest.xml',
        False,
    ),
)

AON_CHECKS = (
    Check(
        'ezpay SI provider stripped',
        'IntelligentSearchIndexablesProvider',
        'AndroidManifest.xml',
        False,
    ),
)

STDID_CHECKS = (
    Check(
        'receiver flags injected',
        'invoke-virtual/range {v0 .. v5}, Landroid/content/Context;->registerReceiver',
    ),
)

# Repacked archives, checked after the extract as shipped in the blob repo.
PATCHED_BLOBS = (
    'system_ext/priv-app/OplusCamera/OplusCamera.apk',
    'system_ext/framework/com.oplus.camera.unit.sdk.jar',
    'system_ext/priv-app/OppoGallery2/OppoGallery2.apk',
    'system_ext/priv-app/AIUnit/AIUnit.apk',
    'system_ext/priv-app/AONService/AONService.apk',
    'system_ext/priv-app/StdID/StdID.apk',
)

def verify_packed_artifacts():
    # Check what actually landed in the blob repo.
    out = Path(__file__).resolve().parent / 'blobs' / 'proprietary'
    for rel in PATCHED_BLOBS:
        name = Path(rel).name
        target = out / rel
        if not target.is_file():
            VERIFY_RESULTS.append((name, 'present in blob repo', False))
            continue
        try:
            with zipfile.ZipFile(target) as z:
                names = z.namelist()
        except (zipfile.BadZipFile, OSError):
            VERIFY_RESULTS.append((name, 'repacked archive readable', False))
            continue
        VERIFY_RESULTS.append((name, 'repacked archive readable', True))
        VERIFY_RESULTS.append((
            name,
            'contains dex',
            any(n.endswith('.dex') for n in names),
        ))

def report_verification() -> bool:
    if not VERIFY_RESULTS:
        color_print('\nno patch verification ran', color=Color.RED)
        return False

    width = max(len(f'{label}: {what}') for label, what, _ in VERIFY_RESULTS)
    failed = [r for r in VERIFY_RESULTS if not r[2]]

    print('\n=== patch verification ===')
    for label, what, ok in VERIFY_RESULTS:
        color_print(
            f'{label}: {what}'.ljust(width) + ('   OK' if ok else '   FAILED'),
            color=Color.GREEN if ok else Color.RED,
        )

    if failed:
        color_print(
            f'\n{len(failed)} of {len(VERIFY_RESULTS)} checks FAILED, the blobs '
            'above shipped without the change they are supposed to carry. Re-derive '
            'the anchor against this dump before building.',
            color=Color.RED,
        )
        return False

    color_print(
        f'\nall {len(VERIFY_RESULTS)} checks passed', color=Color.GREEN
    )
    return True

blob_fixups = {
    # Fail these dlopens so APS takes the Java HEIF route like stock.
    'system_ext/lib64/libAPSClient-cmd-jni.so': blob_fixup()
        .binary_regex_replace(rb'\x00libHeifEncoderWrapper\.so\x00', b'\x00xibHeifEncoderWrapper.so\x00')
        .binary_regex_replace(rb'\x00libNativeWinBuffExchange\.so\x00', b'\x00xibNativeWinBuffExchange.so\x00'),
    'system_ext/lib64/libAPSClient-cmd-jni-extension.oplus.so': blob_fixup()
        .binary_regex_replace(b'libHeifEncoderWrapper\\.so', b'xibHeifEncoderWrapper.so'),
    'system_ext/lib64/libcsextimpl.so': blob_fixup()
        .replace_needed(
            'android.hardware.camera.provider-V3-ndk.so',
            'android.hardware.camera.provider-V4-ndk.so',)
        .replace_needed(
            'android.hardware.camera.device-V3-ndk.so',
            'android.hardware.camera.device-V4-ndk.so',)
        .replace_needed('libbase.so', 'libbase-stock.so'),
    # apktool_patch() expanded for the linker namespace fixup.
    'system_ext/priv-app/OplusCamera/OplusCamera.apk': blob_fixup()
        .apktool_unpack('patches')
        .patch_dir('patches')
        .call(blob_fixup_opluscamera_privapp_linker_ns)
        .call(verify('OplusCamera', *OPLUSCAMERA_CHECKS))
        .apktool_pack()
        .stripzip(),
    # apktool_patch() expanded so the patches can be verified before packing.
    'system_ext/framework/com.oplus.camera.unit.sdk.jar': blob_fixup()
        .apktool_unpack('patches-sdk')
        .patch_dir('patches-sdk')
        .call(verify('sdk.jar', *SDK_CHECKS))
        .apktool_pack()
        .stripzip(),
    # apktool_patch() expanded so the patches can be verified before packing.
    'system_ext/priv-app/OppoGallery2/OppoGallery2.apk': blob_fixup()
        .apktool_unpack('patches-gallery')
        .patch_dir('patches-gallery')
        .call(blob_fixup_gallery_force_flags)
        .call(verify('OppoGallery2', *GALLERY_CHECKS))
        .apktool_pack()
        .stripzip(),
    'system_ext/priv-app/AIUnit/AIUnit.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_src)
        # SI crash: must strip SearchIndexablesProvider even when pyaxml is missing.
        .call(blob_fixup_aiunit_disable_settings)
        .call(blob_fixup_aiunit_si_preference_roots)
        .call(blob_fixup_aiunit_baseos_empty)
        .call(blob_fixup_aiunit_authorize_camera)
        .call(blob_fixup_aiunit_plugin_so_permissions)
        .call(verify('AIUnit', *AIUNIT_CHECKS))
        .apktool_pack()
        .stripzip(),
    'system_ext/priv-app/AONService/AONService.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_src)
        .call(blob_fixup_aon_disable_ezpay_settings)
        .call(verify('AONService', *AON_CHECKS))
        .apktool_pack()
        .stripzip(),
    'system_ext/priv-app/StdID/StdID.apk': blob_fixup()
        .call(blob_fixup_apktool_unpack_src)
        .call(blob_fixup_stdid_receiver_flags)
        .call(verify('StdID', *STDID_CHECKS))
        .apktool_pack()
        .stripzip(),
}

namespace_imports = [
    'vendor/oplus/camera/dodge/blobs',
    'vendor/oneplus/dodge',
    'vendor/oneplus/sm8750-common',
    'hardware/oplus',
    'vendor/qcom/common/system/audio',
    'vendor/qcom/common/system/perf',
]

module = ExtractUtilsModule(
    'blobs',
    'oplus/camera/dodge',
    device_rel_path='vendor/oplus/camera/dodge',
    blob_fixups=blob_fixups,
    lib_fixups=lib_fixups,
    namespace_imports=namespace_imports,
)

# Repacking OppoGallery2 needs over 10 GB of scratch space.
REQUIRED_SCRATCH_BYTES = 24 * 1024**3

def use_scratch_dir_with_space():
    """Point tempfile at a filesystem with room for the apktool work dirs."""
    default_tmp = tempfile.gettempdir()
    if shutil.disk_usage(default_tmp).free >= REQUIRED_SCRATCH_BYTES:
        return

    scratch = os.path.join(
        os.environ.get('XDG_CACHE_HOME') or os.path.expanduser('~/.cache'),
        'extract-utils',
        'scratch',
    )
    os.makedirs(scratch, exist_ok=True)

    os.environ['TMPDIR'] = scratch
    tempfile.tempdir = scratch

    # Java ignores TMPDIR.
    java_options = os.environ.get('JAVA_TOOL_OPTIONS', '')
    os.environ['JAVA_TOOL_OPTIONS'] = (
        f'{java_options} -Djava.io.tmpdir={scratch}'.strip()
    )

    free_gib = shutil.disk_usage(scratch).free / 1024**3
    print(
        f'{default_tmp} is too small for apktool, using {scratch} '
        f'({free_gib:.0f} GiB free)'
    )
    if shutil.disk_usage(scratch).free < REQUIRED_SCRATCH_BYTES:
        print(
            f'warning: {scratch} has under '
            f'{REQUIRED_SCRATCH_BYTES / 1024**3:.0f} GiB free either; the '
            f'OppoGallery2 repack may still fail. Set TMPDIR to somewhere '
            f'with more room.'
        )

# extract-utils has no rule for overlay APKs, copy them from the dump.
OVERLAY_SOURCES = (
    'my_product/overlay/aon.frameworkres.overlay.product.apk',
    'my_product/overlay/OplusAiConfigOverlayCommon/OplusAiConfigOverlayCommon.apk',
    'my_product/overlay/OplusCameraBigBallConfigOverlay/OplusCameraBigBallConfigOverlay.apk',
)


def extract_overlays():
    src_root = None
    for arg in sys.argv[1:]:
        if not arg.startswith('-') and Path(arg).is_dir():
            src_root = Path(arg)
    if src_root is None:
        print('overlays: no dump directory on the command line, skipped')
        return False

    out = Path(__file__).resolve().parent / 'overlays'
    ok = True
    for rel in OVERLAY_SOURCES:
        src = src_root / rel
        dst = out / Path(rel).relative_to('my_product/overlay')
        if not src.is_file():
            VERIFY_RESULTS.append((dst.name, 'present in the dump', False))
            ok = False
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        VERIFY_RESULTS.append((dst.name, 'extracted from the dump', True))
    return ok


if __name__ == '__main__':
    use_scratch_dir_with_space()

    utils = ExtractUtils.device(module)
    utils.run()

    extract_overlays()
    verify_packed_artifacts()
    if not report_verification():
        sys.exit(1)
