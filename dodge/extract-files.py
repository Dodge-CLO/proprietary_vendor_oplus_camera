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
)

# Repacked archives, checked after the extract as shipped in the blob repo.
PATCHED_BLOBS = (
    'system_ext/priv-app/OplusCamera/OplusCamera.apk',
    'system_ext/framework/com.oplus.camera.unit.sdk.jar',
    'system_ext/priv-app/OppoGallery2/OppoGallery2.apk',
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
        .call(verify('OppoGallery2', *GALLERY_CHECKS))
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

if __name__ == '__main__':
    use_scratch_dir_with_space()

    utils = ExtractUtils.device(module)
    utils.run()

    verify_packed_artifacts()
    if not report_verification():
        sys.exit(1)
