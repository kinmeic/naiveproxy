plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val keystoreFile = System.getenv("ANDROID_KEYSTORE_FILE")
val keystorePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
val releaseKeyAlias = System.getenv("ANDROID_KEY_ALIAS")
val releaseKeyPassword = System.getenv("ANDROID_KEY_PASSWORD")
val hasReleaseSigning = listOf(
    keystoreFile,
    keystorePassword,
    releaseKeyAlias,
    releaseKeyPassword,
).all { !it.isNullOrBlank() }

android {
    namespace = "io.nekohasekai.sagernet.plugin.naive"

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = file(keystoreFile!!)
                storePassword = keystorePassword!!
                keyAlias = releaseKeyAlias!!
                keyPassword = releaseKeyPassword!!
            }
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    buildToolsVersion = "36.0.0"

    compileSdk = 36

    defaultConfig {
        minSdk = 24
        targetSdk = 36

        applicationId = "io.nekohasekai.sagernet.plugin.naive"
        versionCode = System.getenv("APK_VERSION_NAME").removePrefix("v").split(".")[0].toInt() * 10 + System.getenv("APK_VERSION_NAME").removePrefix("v").split("-")[1].toInt()
        versionName = System.getenv("APK_VERSION_NAME").removePrefix("v")
        splits.abi {
            isEnable = true
            isUniversalApk = false
            reset()
            include(System.getenv("APK_ABI"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    lint {
        showAll = true
        checkAllWarnings = true
        checkReleaseBuilds = false
        warningsAsErrors = true
    }

    packaging {
        jniLibs.useLegacyPackaging = true
    }

    applicationVariants.all {
        outputs.all {
            this as com.android.build.gradle.internal.api.BaseVariantOutputImpl
            outputFileName =
                outputFileName.replace(project.name, "naiveproxy-plugin-v$versionName")
                    .replace("-release", "")
                    .replace("-oss", "")
        }
    }

    sourceSets.getByName("main") {
        jniLibs.srcDir("libs")
    }
}

tasks.register("verifyReleaseSigning") {
    doLast {
        check(hasReleaseSigning) {
            "Release APK signing is required. Set ANDROID_KEYSTORE_FILE, " +
                "ANDROID_KEYSTORE_PASSWORD, ANDROID_KEY_ALIAS, and " +
                "ANDROID_KEY_PASSWORD."
        }
    }
}

tasks.matching { it.name == "assembleRelease" }.configureEach {
    dependsOn("verifyReleaseSigning")
}
