package io.nekohasekai.sagernet.ui.profile

import android.text.InputType
import android.widget.FrameLayout
import androidx.lifecycle.lifecycleScope
import androidx.preference.EditTextPreference
import androidx.preference.Preference
import androidx.preference.PreferenceCategory
import androidx.preference.SwitchPreference
import androidx.preference.PreferenceFragmentCompat
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import io.nekohasekai.sagernet.R
import io.nekohasekai.sagernet.bg.CoreServiceClient
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.ktx.Logs
import io.nekohasekai.sagernet.ktx.dp2px
import io.nekohasekai.sagernet.outbound.json.JsonInput
import io.nekohasekai.sagernet.outbound.types.WireGuard
import io.nekohasekai.sagernet.outbound.types.WireGuardChecks
import io.nekohasekai.sagernet.ui.ValidationForm
import io.nekohasekai.sagernet.ui.warp.WarpClient
import io.nekohasekai.sagernet.ui.warp.WarpGenerate
import io.nekohasekai.sagernet.ui.warp.setFieldText
import io.nekohasekai.sagernet.validation.Validation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** WireGuard / AmneziaWG: the endpoint lives in `peer.*`, the interface in the top-level fields. */
class WireGuardSettingsActivity : BindingSettingsActivity<WireGuard>() {

    override fun createEntity() = WireGuard()
    override val preferencesResource = R.xml.wireguard_preferences

    init {
        pbm.text("name")
        pbm.text("peer.address")
        pbm.int("peer.port")
        pbm.text("address")
        pbm.text("private_key")
        pbm.text("peer.public_key")
        pbm.text("peer.pre_shared_key")
        pbm.text("peer.reserved")
        pbm.text("peer.persistent_keepalive")
        pbm.int("mtu")
        pbm.bool("system")
        pbm.int("worker_count")
        pbm.text("udp_timeout")
        pbm.bool("enable_amnezia")
        for (field in listOf("jc", "jmin", "jmax", "s1", "s2", "s3", "s4")) pbm.int(field)
        for (field in listOf(
            "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5", "header_protection_key", "content_padding_addition",
            "rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts",
        )) pbm.text(field)
        pbm.bool("random_trailers")
        pbm.bool("disable_cookies")
    }

    /** edit_wireguard.cpp onEnd: reserved and addresses take commas as well as lines, bare addresses get /32 or /128. */
    override fun WireGuard.serialize() {
        pbm.fromCacheAll(this)
        WireGuardChecks.wireguardReserved(reservedText(DataStore.profileCacheStore.getString("peer.reserved").orEmpty()), peer.reserved)
        address = address.flatMapTo(ArrayList()) { it.split(',') }
        fixAddress()
    }

    private fun reservedText(text: String) = text.replace('\n', ',')

    override fun issueKey(field: String): String? = when (field) {
        "server" -> "peer.address"
        "server_port" -> "peer.port"
        "public_key", "pre_shared_key", "reserved" -> "peer.$field"
        "persistent_keepalive_interval" -> "peer.persistent_keepalive"
        else -> null
    }

    /**
     * edit_wireguard.cpp / edit_wireguard_amnezia.cpp bindValidation, for the text the bindings lose: reserved bytes
     * and integers they would turn into 0. WireGuard.validate covers the rest, Amnezia rows included.
     */
    override fun ValidationForm.bindValidation() {
        val intMax = Int.MAX_VALUE.toLong()
        bind("peer.reserved") { WireGuardChecks.wireguardReserved(reservedText(it)) }
        for (key in listOf("mtu", "worker_count", "jc", "jmin", "jmax")) bind(key, Validation.Rules.int(0, intMax))
        for (key in listOf("s1", "s2", "s3", "s4")) bind(key, Validation.Rules.int(0, 65535))
    }

    override fun PreferenceFragmentCompat.onPreferencesCreated() {
        portInput("peer.port")
        numberInput("mtu", "worker_count", "jc", "jmin", "jmax", "s1", "s2", "s3", "s4")
        passwordSummary("private_key", "peer.pre_shared_key")
        multilineInput("address", "peer.reserved")
        // stored one per line, shown on one
        findPreference<EditTextPreference>("peer.reserved")?.summaryProvider =
            Preference.SummaryProvider<EditTextPreference> { pref ->
                pref.text.orEmpty().lines().map { it.trim() }.filter { it.isNotEmpty() }.joinToString(", ")
                    .ifEmpty { getString(androidx.preference.R.string.not_set) }
            }

        val amneziaPropertyKeys = listOf(
            "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
            "i1", "i2", "i3", "i4", "i5", KEY_QUIC_SIGNATURE, "header_protection_key",
            "content_padding_addition", "rekey_after_time", "rekey_timeout", "reject_after_time",
            "keepalive_timeout", "max_handshake_attempts", "random_trailers", "disable_cookies",
        )
        var showAmneziaProperties = findPreference<SwitchPreference>("enable_amnezia")?.isChecked == true
        fun setAmneziaPropertiesVisible(visible: Boolean) {
            showAmneziaProperties = visible
            amneziaPropertyKeys.forEach { key -> findPreference<Preference>(key)?.isVisible = visible }
        }
        setAmneziaPropertiesVisible(showAmneziaProperties)
        onSwitch("enable_amnezia") { on ->
            if (on) setAmneziaPropertiesVisible(true)
        }

        findPreference<Preference>("amneziaQuickActions")?.setOnPreferenceClickListener {
            val compatibilitySet = isCompatibilityPreset(this)
            val options = arrayOf(
                getString(if (showAmneziaProperties) R.string.hide_amnezia_properties else R.string.show_amnezia_properties),
                getString(if (compatibilitySet) R.string.remove_amnezia_compatibility else R.string.enable_amnezia_compatibility),
                getString(R.string.mimic_quic),
                getString(R.string.mimic_dns),
                getString(R.string.mimic_sip),
            )
            MaterialAlertDialogBuilder(this@WireGuardSettingsActivity)
                .setTitle(R.string.amnezia_quick_actions)
                .setItems(options) { _, which ->
                    when (which) {
                        0 -> setAmneziaPropertiesVisible(!showAmneziaProperties)
                        1 -> {
                            if (compatibilitySet) resetAmneziaProperties(this)
                            else applyAmneziaCompatibility(this)
                            setAmneziaPropertiesVisible(!compatibilitySet)
                        }
                        2 -> {
                            applyAmneziaMimic(this, "QUIC")
                            setAmneziaPropertiesVisible(true)
                        }
                        3 -> {
                            applyAmneziaMimic(this, "DNS")
                            setAmneziaPropertiesVisible(true)
                        }
                        4 -> {
                            applyAmneziaMimic(this, "SIP")
                            setAmneziaPropertiesVisible(true)
                        }
                    }
                }
                .show()
            true
        }

        // edit_wireguard.cpp:39-51
        WarpGenerate.bindEditorRow(
            this@WireGuardSettingsActivity, this, WarpClient.TUNNEL_WIREGUARD, R.string.warp_wireguard_profile_name,
        ) { identity ->
            setFieldText("private_key", identity.privateKey)
            setFieldText("peer.public_key", identity.peerPublicKey)
            setFieldText("address", identity.addresses.joinToString("\n"))
            setFieldText("mtu", "1280")
            setFieldText("peer.persistent_keepalive", "30")
            identity.endpointHostPort()?.let { (host, port) ->
                setFieldText("peer.address", host)
                setFieldText("peer.port", port)
            }
            setFieldText("peer.reserved", identity.reserved.joinToString("\n"))
        }

        findPreference<Preference>(KEY_QUIC_SIGNATURE)?.setOnPreferenceClickListener { button ->
            askSignatureDomain(this, button)
            true
        }
    }

    private fun isCompatibilityPreset(screen: PreferenceFragmentCompat): Boolean {
        fun value(key: String, fallback: String = "") =
            screen.findPreference<EditTextPreference>(key)?.text?.ifBlank { fallback } ?: fallback
        return (value("s1", "0").toIntOrNull() ?: 0) == 0 &&
            (value("s2", "0").toIntOrNull() ?: 0) == 0 &&
            value("h1") == "1" && value("h2") == "2" &&
            value("h3") == "3" && value("h4") == "4"
    }

    private fun enableAmnezia(screen: PreferenceFragmentCompat) {
        screen.findPreference<SwitchPreference>("enable_amnezia")?.isChecked = true
    }

    private fun ensureAmneziaBaseParameters(screen: PreferenceFragmentCompat) {
        val defaults = linkedMapOf(
            "jc" to "4", "jmin" to "40", "jmax" to "70",
            "s1" to "0", "s2" to "0", "s3" to "0", "s4" to "0",
            "h1" to "1", "h2" to "2", "h3" to "3", "h4" to "4",
        )
        defaults.forEach { (key, value) ->
            if (screen.findPreference<EditTextPreference>(key)?.text.isNullOrBlank()) {
                screen.setFieldText(key, value)
            }
        }
        enableAmnezia(screen)
    }

    private fun applyAmneziaCompatibility(screen: PreferenceFragmentCompat) {
        enableAmnezia(screen)
        mapOf(
            "jc" to "4", "jmin" to "40", "jmax" to "70",
            "s1" to "0", "s2" to "0", "s3" to "0", "s4" to "0",
            "h1" to "1", "h2" to "2", "h3" to "3", "h4" to "4",
        ).forEach { (key, value) -> screen.setFieldText(key, value) }
    }

    private fun resetAmneziaProperties(screen: PreferenceFragmentCompat) {
        listOf(
            "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
            "i1", "i2", "i3", "i4", "i5", "header_protection_key", "content_padding_addition",
            "rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout",
            "max_handshake_attempts",
        ).forEach { screen.setFieldText(it, "") }
        screen.findPreference<SwitchPreference>("random_trailers")?.isChecked = false
        screen.findPreference<SwitchPreference>("disable_cookies")?.isChecked = false
        screen.findPreference<SwitchPreference>("enable_amnezia")?.isChecked = false
    }

    private fun applyAmneziaMimic(screen: PreferenceFragmentCompat, mode: String) {
        ensureAmneziaBaseParameters(screen)
        when (mode) {
            "QUIC" -> {
                screen.setFieldText("i1", "<b 0xc1ff000012508394c8f03e51570800449f0dbc195a0000f3a694c75775b4e546172ce9e047cd0b5bee5181648c727adc87f7eae54473ec6cba6bdad4f59823174b769f12358abd292d4f3286934484fb8b239c38732e1f3bbbc6a003056487eb8b5c88b9fd9279ffff3b0f4ecf95c4624db6d65d4113329ee9b0bf8cdd7c8a8d72806d55df25ecb66488bc119d7c9a29abaf99bb33c56b08ad8c26995f838bb3b7a3d5c1858b8ec06b839db2dcf918d5ea9317f1acd6b663cc8925868e2f6a1bda546695f3c3f33175944db4a11a346afb07e78489e509b02add51b7b203eda5c330b03641179a31fbba9b56ce00f3d5b5e3d7d9c5429aebb9576f2f7eacbe27bc1b8082aaf68fb69c921aa5d33ec0c8510410865a178d86d7e54122d55ef2c2bbc040be46d7fece73fe8a1b24495ec160df2da9b20a7ba2f26dfa2a44366dbc63de5cd7d7c94c57172fe6d79c901f025c0010b02c89b395402c009f62dc053b8067a1e0ed0a1e0cf5087d7f78cbd94afe0c3dd55d2d4b1a5cfe2b68b86264e351d1dcd858783a240f893f008ceed743d969b8f735a1677ead960b1fb1ecc5ac83c273b49288d02d7286207e663c45e1a7baf50640c91e762941cf380ce8d79f3e86767fbbcd25b42ef70ec334835a3a6d792e170a432ce0cb7bde9aaa1e75637c1c34ae5fef4338f53db8b13a4d2df594efbfa08784543815c9c0d487bddfa1539bc252cf43ec3686e9802d651cfd2a829a06a9f332a733a4a8aed80efe3478093fbc69c8608146b3f16f1a5c4eac9320da49f1afa5f538ddecbbe7888f435512d0dd74fd9b8c99e3145ba84410d8ca9a36dd884109e76e5fb8222a52e1473da168519ce7a8a3c32e9149671b16724c6c5c51bb5cd64fb591e567fb78b10f9f6fee62c276f282a7df6bcf7c17747bc9a81e6c9c3b032fdd0e1c3ac9eaa5077de3ded18b2ed4faf328f49875af2e36ad5ce5f6cc99ef4b60e57b3b5b9c9fcbcd4cfb3975e70ce4c2506bcd71fef0e53592461504e3d42c885caab21b782e26294c6a9d61118cc40a26f378441ceb48f31a362bf8502a723a36c63502229a462cc2a3796279a5e3a7f81a68c7f81312c381cc16a4ab03513a51ad5b54306ec1d78a5e47e2b15e5b7a1438e5b8b2882dbdad13d6a4a8c3558cae043501b68eb3b040067152>")
                screen.setFieldText("i2", "<b 0x0000000000010000000000000000000000000000000000000000000000000000>")
            }
            "DNS" -> {
                screen.setFieldText("i1", "<b 0x123401000001000000000000076578616d706c6503636f6d0000010001>")
                screen.setFieldText("i2", "")
            }
            "SIP" -> {
                screen.setFieldText("i1", "<b 0x494e56495445207369703a626f624062696c6f78692e636f6d205349502f322e300d0a5669613a205349502f322e302f55445020706333332e61746c616e74612e636f6d3b6272616e63683d7a39684734624b3737366173646864730d0a4d61782d466f7277617264733a2037300d0a546f3a20426f62203c7369703a626f624062696c6f78692e636f6d3e0d0a46726f6d3a20416c696365203c7369703a616c6963654061746c616e74612e636f6d3e3b7461673d313932383330313737340d0a43616c6c2d49443a20613834623463373665363637313040706333332e61746c616e74612e636f6d0d0a435365713a2033313431353920494e564954450d0a436f6e746163743a203c7369703a616c69636540706333332e61746c616e74612e636f6d3e0d0a436f6e74656e742d547970653a206170706c69636174696f6e2f7364700d0a436f6e74656e742d4c656e6774683a20300d0a0d0a>")
                screen.setFieldText("i2", "<b 0x5349502f322e302031303020547279696e670d0a5669613a205349502f322e302f55445020706333332e61746c616e74612e636f6d3b6272616e63683d7a39684734624b3737366173646864730d0a546f3a20426f62203c7369703a626f624062696c6f78692e636f6d3e0d0a46726f6d3a20416c696365203c7369703a616c6963654061746c616e74612e636f6d3e3b7461673d313932383330313737340d0a43616c6c2d49443a20613834623463373665363637313040706333332e61746c616e74612e636f6d0d0a435365713a2033313431353920494e564954450d0a436f6e74656e742d4c656e6774683a20300d0a0d0a>")
            }
        }
        val category = screen.findPreference<PreferenceCategory>("amneziaCategory")
        listOf(
            "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
            "i1", "i2", "i3", "i4", "i5", KEY_QUIC_SIGNATURE, "header_protection_key",
            "content_padding_addition", "rekey_after_time", "rekey_timeout", "reject_after_time",
            "keepalive_timeout", "max_handshake_attempts", "random_trailers", "disable_cookies",
        ).forEach { key -> category?.findPreference<Preference>(key)?.isVisible = true }
    }

    // edit_wireguard_amnezia.cpp generateSignature
    private fun askSignatureDomain(screen: PreferenceFragmentCompat, button: Preference) {
        val layout = TextInputLayout(this).apply { hint = getString(R.string.amnezia_quic_signature_domain) }
        val input = TextInputEditText(layout.context).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            isSingleLine = true
            setText(lastSignatureDomain)
        }
        layout.addView(input)
        val container = FrameLayout(this).apply {
            setPadding(dp2px(20), dp2px(12), dp2px(20), 0)
            addView(layout)
        }
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.amnezia_quic_signature_title)
            .setView(container)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                val domain = input.text?.toString()?.trim().orEmpty()
                if (domain.isNotEmpty()) {
                    lastSignatureDomain = domain
                    generateSignature(screen, button, domain)
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun generateSignature(screen: PreferenceFragmentCompat, button: Preference, domain: String) {
        val idle = button.summary
        button.isEnabled = false
        button.summary = getString(R.string.generating)
        lifecycleScope.launch {
            val raw = try {
                withContext(Dispatchers.IO) { CoreServiceClient.call { it.genQuicSignature(domain) } }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Logs.w(e)
                null
            }
            button.summary = idle
            button.isEnabled = true
            val result = raw?.let { JsonInput.parseObjectOrNull(it) }
            val packets = result?.array("packets")?.strings().orEmpty()
            val error = if (result == null) getString(R.string.warp_core_unreachable) else result.string("error")
            if (error.isNotEmpty() || packets.isEmpty()) {
                MaterialAlertDialogBuilder(this@WireGuardSettingsActivity)
                    .setTitle(R.string.amnezia_quic_signature_failed)
                    .apply { if (error.isNotEmpty()) setMessage(error) }
                    .setPositiveButton(android.R.string.ok, null)
                    .show()
                return@launch
            }
            // An "Edit as JSON" round trip may have rebuilt the screen meanwhile.
            val target = supportFragmentManager.findFragmentById(R.id.settings) as? PreferenceFragmentCompat ?: screen
            SIGNATURE_FIELDS.forEachIndexed { i, key -> target.setFieldText(key, packets.getOrElse(i) { "" }) }
        }
    }

    private companion object {
        const val KEY_QUIC_SIGNATURE = "amneziaQuicSignature"
        val SIGNATURE_FIELDS = listOf("i1", "i2", "i3", "i4", "i5")

        // Offered again next time, like the desktop's lastSignatureDomain.
        var lastSignatureDomain = ""
    }

}
