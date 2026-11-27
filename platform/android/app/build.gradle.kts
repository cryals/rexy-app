plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.rexy.r3x"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.rexy.r3x"
        // Minimum Android 10 (API 29): ensures Scoped Storage, modern VpnService Builder APIs,
        // TLS 1.3 platform support, and AES-GCM AndroidKeyStore without legacy fallbacks.
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        val ksPath = System.getenv("R3X_KEYSTORE_PATH")
        if (!ksPath.isNullOrBlank()) {
            create("release") {
                storeFile = file(ksPath)
                storePassword = System.getenv("R3X_KEYSTORE_PASSWORD") ?: ""
                keyAlias = System.getenv("R3X_KEY_ALIAS") ?: ""
                keyPassword = System.getenv("R3X_KEY_PASSWORD") ?: ""
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            val releaseSign = signingConfigs.findByName("release")
            if (releaseSign != null) {
                signingConfig = releaseSign
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.8.0")
}
