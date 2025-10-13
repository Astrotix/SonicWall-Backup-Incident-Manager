// Translations for SonicWall Backup Incident Manager
const translations = {
    en: {
        // Sidebar
        sidebar: {
            title: "SonicWall Backup Incident Manager",
            firewalls: "Firewalls",
            wanManagement: "WAN Management",
            localUsers: "Local Users",
            ldap: "LDAP",
            radius: "RADIUS",
            tacacs: "TACACS+",
            sso: "SSO",
            ipsecVpn: "IPSec VPN",
            sslVpn: "SSL VPN",
            pppoe: "PPPoE/PPTP/L2TP",
            cse: "CSE",
            analytics: "Analytics"
        },
        // Header
        header: {
            title: "Firewall Management",
            total: "Total",
            connected: "Connected",
            issues: "Issues",
            resolved: "Resolved"
        },
        // Disclaimer
        disclaimer: {
            title: "Disclaimer:",
            text: "This is NOT an official SonicWall tool. This application is provided as-is for management purposes only. The user assumes all responsibility for its use. Always follow security best practices and backup your configurations.",
            contact: "For issues or feature requests, contact"
        },
        // Common
        common: {
            add: "Add",
            edit: "Edit",
            delete: "Delete",
            save: "Save",
            cancel: "Cancel",
            test: "Test",
            audit: "Audit",
            refresh: "Refresh All",
            clearAll: "Clear All",
            name: "Name",
            ip: "IP Address",
            username: "Username",
            password: "Password",
            status: "Status",
            actions: "Actions",
            search: "Search firewalls...",
            noResults: "No results found",
            loading: "Loading...",
            error: "Error",
            success: "Success"
        },
        // Firewall Management
        firewalls: {
            title: "Firewalls",
            subtitle: "Manage your SonicWall devices",
            addFirewall: "Add Firewall",
            noFirewalls: "No firewalls added",
            addFirst: "Add your first firewall using the form above",
            apiUrl: "API URL",
            lastChecked: "Last Checked",
            connected: "Connected",
            disconnected: "Disconnected",
            testing: "Testing"
        },
        // Submenu
        submenu: {
            monitoring: "Monitoring",
            remediation: "Remediation"
        },
        // WAN Management
        wan: {
            title: "WAN Management",
            subtitle: "WAN-to-WAN management rules and security remediation",
            check: "Check WAN Management",
            noData: "No WAN Management Data",
            autoLoading: "Loading WAN management rules automatically...",
            noRules: "No WAN management rules found",
            rulesFound: "WAN management rules detected",
            secure: "No WAN zones in management",
            atRisk: "WAN zones found in management",
            remediate: "Start WAN Remediation",
            remediating: "Remediating...",
            resolved: "Resolved",
            issues: "Issues detected"
        },
        // SSO
        sso: {
            title: "SSO (Single Sign-On)",
            subtitle: "SSO authentication monitoring and remediation",
            check: "Check SSO",
            noData: "No SSO Data",
            enabled: "SSO Enabled",
            disabled: "SSO Disabled",
            secure: "Secure authentication method",
            weak: "Weak authentication method detected",
            remediate: "Remediate SSO"
        },
        // CSE
        cse: {
            title: "Cloud Secure Edge (CSE)",
            subtitle: "Cloud Secure Edge connectors and configuration",
            check: "Check CSE",
            noData: "No CSE Data",
            enabled: "CSE Enabled",
            disabled: "CSE Disabled",
            remediate: "Start CSE Remediation",
            reactivate: "Reactivate CSE Now",
            manualSteps: "Important Note on Remediation",
            step1: "Log in to MySonicWall",
            step2: "Go to the Products page and select the Tenant",
            step3: "Select the serial number for Cloud Secure Edge",
            step4: "Click on 'Firewall Connection'",
            step5: "Remove association by clicking the trash icon",
            timerText: "After completing the manual steps, a 30-second timer will start",
            waiting: "Waiting for reactivation"
        },
        // VPN
        vpn: {
            ssl: {
                title: "SSL VPN",
                subtitle: "SSL VPN certificate and authentication checks"
            },
            ipsec: {
                title: "IPSec VPN",
                subtitle: "IPSec VPN pre-shared keys and certificate validation"
            },
            check: "Check VPN",
            noData: "No VPN Data",
            secure: "VPN configuration secure",
            issues: "VPN configuration issues detected",
            remediate: "Remediate VPN"
        },
        // Users
        users: {
            local: {
                title: "Local Users",
                subtitle: "Local user accounts and weak password detection"
            },
            ldap: {
                title: "LDAP",
                subtitle: "LDAP server configuration and certificate validation"
            },
            radius: {
                title: "RADIUS",
                subtitle: "RADIUS server configuration and secret verification"
            },
            tacacs: {
                title: "TACACS+",
                subtitle: "TACACS+ authentication server checks"
            },
            check: "Check Users",
            noData: "No User Data",
            weakPasswords: "Weak passwords detected",
            secure: "All users secure",
            remediate: "Remediate Users"
        },
        // Analytics
        analytics: {
            title: "Analytics & Reporting",
            subtitle: "Global security insights and firewall performance metrics",
            globalOverview: "Global Security Overview",
            securityScores: "Firewall Security Scores",
            moduleDistribution: "Module Status Distribution",
            ranking: "Firewall Security Ranking",
            totalFirewalls: "Total Firewalls",
            averageScore: "Average Security Score",
            goodStatus: "Good Status",
            warningStatus: "Warning Status",
            criticalStatus: "Critical Status",
            inMonitoring: "In monitoring",
            acrossAll: "Across all devices",
            ofTotal: "of total",
            displayingAll: "Displaying all",
            scrollMore: "firewalls (scroll to see more)",
            resolved: "resolved"
        },
        // Audit Dashboard
        audit: {
            title: "Security Audit",
            analyzing: "Analyzing security modules...",
            securityAnalysis: "Security Analysis",
            pointsEarned: "Security Points Earned",
            resolved: "Resolved",
            atRisk: "At Risk",
            modulesOverview: "Security Modules Overview",
            noIssues: "No issues detected",
            issuesDetected: "Issues detected",
            notChecked: "Not checked",
            timerActive: "Timer active - Pending"
        },
        // Status messages
        status: {
            testSuccess: "Connection test successful",
            testFailed: "Connection test failed",
            firewallAdded: "Firewall added successfully",
            firewallUpdated: "Firewall updated successfully",
            firewallDeleted: "Firewall deleted successfully",
            remediationStarted: "Remediation started",
            remediationComplete: "Remediation completed successfully",
            remediationFailed: "Remediation failed",
            checkComplete: "Security check completed"
        }
    },
    fr: {
        // Sidebar
        sidebar: {
            title: "SonicWall Backup Incident Manager",
            firewalls: "Firewalls",
            wanManagement: "Gestion WAN",
            localUsers: "Utilisateurs Locaux",
            ldap: "LDAP",
            radius: "RADIUS",
            tacacs: "TACACS+",
            sso: "SSO",
            ipsecVpn: "VPN IPSec",
            sslVpn: "VPN SSL",
            pppoe: "PPPoE/PPTP/L2TP",
            cse: "CSE",
            analytics: "Analytique"
        },
        // Header
        header: {
            title: "Gestion des Firewalls",
            total: "Total",
            connected: "Connectés",
            issues: "Problèmes",
            resolved: "Résolus"
        },
        // Disclaimer
        disclaimer: {
            title: "Avertissement :",
            text: "Ceci n'est PAS un outil officiel SonicWall. Cette application est fournie telle quelle à des fins de gestion uniquement. L'utilisateur assume l'entière responsabilité de son utilisation. Suivez toujours les meilleures pratiques de sécurité et sauvegardez vos configurations.",
            contact: "Pour les problèmes ou demandes de fonctionnalités, contactez"
        },
        // Common
        common: {
            add: "Ajouter",
            edit: "Modifier",
            delete: "Supprimer",
            save: "Enregistrer",
            cancel: "Annuler",
            test: "Tester",
            audit: "Audit",
            refresh: "Tout actualiser",
            clearAll: "Tout effacer",
            name: "Nom",
            ip: "Adresse IP",
            username: "Nom d'utilisateur",
            password: "Mot de passe",
            status: "Statut",
            actions: "Actions",
            search: "Rechercher des firewalls...",
            noResults: "Aucun résultat trouvé",
            loading: "Chargement...",
            error: "Erreur",
            success: "Succès"
        },
        // Firewall Management
        firewalls: {
            title: "Firewalls",
            subtitle: "Gérez vos équipements SonicWall",
            addFirewall: "Ajouter un Firewall",
            noFirewalls: "Aucun firewall ajouté",
            addFirst: "Ajoutez votre premier firewall en utilisant le formulaire ci-dessus",
            apiUrl: "URL de l'API",
            lastChecked: "Dernière vérification",
            connected: "Connecté",
            disconnected: "Déconnecté",
            testing: "Test en cours"
        },
        // Submenu
        submenu: {
            monitoring: "Surveillance",
            remediation: "Remédiation"
        },
        // WAN Management
        wan: {
            title: "Gestion WAN",
            subtitle: "Règles de gestion WAN-to-WAN et remédiation de sécurité",
            check: "Vérifier la gestion WAN",
            noData: "Aucune donnée de gestion WAN",
            autoLoading: "Chargement automatique des règles de gestion WAN...",
            noRules: "Aucune règle de gestion WAN trouvée",
            rulesFound: "Règles de gestion WAN détectées",
            secure: "Aucune zone WAN dans la gestion",
            atRisk: "Zones WAN trouvées dans la gestion",
            remediate: "Démarrer la remédiation WAN",
            remediating: "Remédiation en cours...",
            resolved: "Résolu",
            issues: "Problèmes détectés"
        },
        // SSO
        sso: {
            title: "SSO (Authentification unique)",
            subtitle: "Surveillance et remédiation de l'authentification SSO",
            check: "Vérifier SSO",
            noData: "Aucune donnée SSO",
            enabled: "SSO activé",
            disabled: "SSO désactivé",
            secure: "Méthode d'authentification sécurisée",
            weak: "Méthode d'authentification faible détectée",
            remediate: "Remédier SSO"
        },
        // CSE
        cse: {
            title: "Cloud Secure Edge (CSE)",
            subtitle: "Connecteurs et configuration Cloud Secure Edge",
            check: "Vérifier CSE",
            noData: "Aucune donnée CSE",
            enabled: "CSE activé",
            disabled: "CSE désactivé",
            remediate: "Démarrer la remédiation CSE",
            reactivate: "Réactiver CSE maintenant",
            manualSteps: "Note importante sur la remédiation",
            step1: "Connectez-vous à MySonicWall",
            step2: "Allez sur la page Produits et sélectionnez le Tenant",
            step3: "Sélectionnez le numéro de série pour Cloud Secure Edge",
            step4: "Cliquez sur 'Connexion Firewall'",
            step5: "Supprimez l'association en cliquant sur l'icône corbeille",
            timerText: "Après avoir effectué les étapes manuelles, un compte à rebours de 30 secondes démarrera",
            waiting: "En attente de réactivation"
        },
        // VPN
        vpn: {
            ssl: {
                title: "VPN SSL",
                subtitle: "Vérification des certificats et de l'authentification VPN SSL"
            },
            ipsec: {
                title: "VPN IPSec",
                subtitle: "Validation des clés pré-partagées et certificats VPN IPSec"
            },
            check: "Vérifier VPN",
            noData: "Aucune donnée VPN",
            secure: "Configuration VPN sécurisée",
            issues: "Problèmes de configuration VPN détectés",
            remediate: "Remédier VPN"
        },
        // Users
        users: {
            local: {
                title: "Utilisateurs locaux",
                subtitle: "Comptes utilisateurs locaux et détection de mots de passe faibles"
            },
            ldap: {
                title: "LDAP",
                subtitle: "Configuration serveur LDAP et validation des certificats"
            },
            radius: {
                title: "RADIUS",
                subtitle: "Configuration serveur RADIUS et vérification des secrets"
            },
            tacacs: {
                title: "TACACS+",
                subtitle: "Vérification des serveurs d'authentification TACACS+"
            },
            check: "Vérifier les utilisateurs",
            noData: "Aucune donnée utilisateur",
            weakPasswords: "Mots de passe faibles détectés",
            secure: "Tous les utilisateurs sont sécurisés",
            remediate: "Remédier les utilisateurs"
        },
        // Analytics
        analytics: {
            title: "Analytique et rapports",
            subtitle: "Aperçu global de la sécurité et métriques de performance des firewalls",
            globalOverview: "Vue d'ensemble globale de la sécurité",
            securityScores: "Scores de sécurité des firewalls",
            moduleDistribution: "Distribution du statut des modules",
            ranking: "Classement de sécurité des firewalls",
            totalFirewalls: "Total des firewalls",
            averageScore: "Score de sécurité moyen",
            goodStatus: "Statut bon",
            warningStatus: "Statut avertissement",
            criticalStatus: "Statut critique",
            inMonitoring: "En surveillance",
            acrossAll: "Sur tous les équipements",
            ofTotal: "du total",
            displayingAll: "Affichage de tous les",
            scrollMore: "firewalls (faites défiler pour en voir plus)",
            resolved: "résolus"
        },
        // Audit Dashboard
        audit: {
            title: "Audit de sécurité",
            analyzing: "Analyse des modules de sécurité...",
            securityAnalysis: "Analyse de sécurité",
            pointsEarned: "Points de sécurité gagnés",
            resolved: "Résolu",
            atRisk: "À risque",
            modulesOverview: "Vue d'ensemble des modules de sécurité",
            noIssues: "Aucun problème détecté",
            issuesDetected: "Problèmes détectés",
            notChecked: "Non vérifié",
            timerActive: "Minuteur actif - En attente"
        },
        // Status messages
        status: {
            testSuccess: "Test de connexion réussi",
            testFailed: "Test de connexion échoué",
            firewallAdded: "Firewall ajouté avec succès",
            firewallUpdated: "Firewall mis à jour avec succès",
            firewallDeleted: "Firewall supprimé avec succès",
            remediationStarted: "Remédiation démarrée",
            remediationComplete: "Remédiation terminée avec succès",
            remediationFailed: "Remédiation échouée",
            checkComplete: "Vérification de sécurité terminée"
        }
    },
    es: {
        // Sidebar
        sidebar: {
            title: "SonicWall Backup Incident Manager",
            firewalls: "Firewalls",
            wanManagement: "Gestión WAN",
            localUsers: "Usuarios Locales",
            ldap: "LDAP",
            radius: "RADIUS",
            tacacs: "TACACS+",
            sso: "SSO",
            ipsecVpn: "VPN IPSec",
            sslVpn: "VPN SSL",
            pppoe: "PPPoE/PPTP/L2TP",
            cse: "CSE",
            analytics: "Analítica"
        },
        // Header
        header: {
            title: "Gestión de Firewalls",
            total: "Total",
            connected: "Conectados",
            issues: "Problemas",
            resolved: "Resueltos"
        },
        // Disclaimer
        disclaimer: {
            title: "Descargo de responsabilidad:",
            text: "Esta NO es una herramienta oficial de SonicWall. Esta aplicación se proporciona tal cual solo con fines de gestión. El usuario asume toda la responsabilidad por su uso. Siempre siga las mejores prácticas de seguridad y haga copias de seguridad de sus configuraciones.",
            contact: "Para problemas o solicitudes de funciones, contacte con"
        },
        // Common
        common: {
            add: "Añadir",
            edit: "Editar",
            delete: "Eliminar",
            save: "Guardar",
            cancel: "Cancelar",
            test: "Probar",
            audit: "Auditoría",
            refresh: "Actualizar todo",
            clearAll: "Borrar todo",
            name: "Nombre",
            ip: "Dirección IP",
            username: "Usuario",
            password: "Contraseña",
            status: "Estado",
            actions: "Acciones",
            search: "Buscar firewalls...",
            noResults: "No se encontraron resultados",
            loading: "Cargando...",
            error: "Error",
            success: "Éxito"
        },
        // Firewall Management
        firewalls: {
            title: "Firewalls",
            subtitle: "Administre sus dispositivos SonicWall",
            addFirewall: "Añadir Firewall",
            noFirewalls: "No se han añadido firewalls",
            addFirst: "Añada su primer firewall usando el formulario de arriba",
            apiUrl: "URL de la API",
            lastChecked: "Última comprobación",
            connected: "Conectado",
            disconnected: "Desconectado",
            testing: "Probando"
        },
        // Submenu
        submenu: {
            monitoring: "Monitoreo",
            remediation: "Remediación"
        },
        // WAN Management
        wan: {
            title: "Gestión WAN",
            subtitle: "Reglas de gestión WAN-to-WAN y remediación de seguridad",
            check: "Verificar gestión WAN",
            noData: "No hay datos de gestión WAN",
            autoLoading: "Cargando reglas de gestión WAN automáticamente...",
            noRules: "No se encontraron reglas de gestión WAN",
            rulesFound: "Reglas de gestión WAN detectadas",
            secure: "No hay zonas WAN en gestión",
            atRisk: "Zonas WAN encontradas en gestión",
            remediate: "Iniciar remediación WAN",
            remediating: "Remediando...",
            resolved: "Resuelto",
            issues: "Problemas detectados"
        },
        // SSO
        sso: {
            title: "SSO (Inicio de sesión único)",
            subtitle: "Monitoreo y remediación de autenticación SSO",
            check: "Verificar SSO",
            noData: "No hay datos SSO",
            enabled: "SSO habilitado",
            disabled: "SSO deshabilitado",
            secure: "Método de autenticación seguro",
            weak: "Método de autenticación débil detectado",
            remediate: "Remediar SSO"
        },
        // CSE
        cse: {
            title: "Cloud Secure Edge (CSE)",
            subtitle: "Conectores y configuración de Cloud Secure Edge",
            check: "Verificar CSE",
            noData: "No hay datos CSE",
            enabled: "CSE habilitado",
            disabled: "CSE deshabilitado",
            remediate: "Iniciar remediación CSE",
            reactivate: "Reactivar CSE ahora",
            manualSteps: "Nota importante sobre la remediación",
            step1: "Inicie sesión en MySonicWall",
            step2: "Vaya a la página de Productos y seleccione el Tenant",
            step3: "Seleccione el número de serie para Cloud Secure Edge",
            step4: "Haga clic en 'Conexión de Firewall'",
            step5: "Elimine la asociación haciendo clic en el icono de papelera",
            timerText: "Después de completar los pasos manuales, se iniciará un temporizador de 30 segundos",
            waiting: "Esperando reactivación"
        },
        // VPN
        vpn: {
            ssl: {
                title: "VPN SSL",
                subtitle: "Verificación de certificados y autenticación VPN SSL"
            },
            ipsec: {
                title: "VPN IPSec",
                subtitle: "Validación de claves precompartidas y certificados VPN IPSec"
            },
            check: "Verificar VPN",
            noData: "No hay datos VPN",
            secure: "Configuración VPN segura",
            issues: "Problemas de configuración VPN detectados",
            remediate: "Remediar VPN"
        },
        // Users
        users: {
            local: {
                title: "Usuarios locales",
                subtitle: "Cuentas de usuarios locales y detección de contraseñas débiles"
            },
            ldap: {
                title: "LDAP",
                subtitle: "Configuración del servidor LDAP y validación de certificados"
            },
            radius: {
                title: "RADIUS",
                subtitle: "Configuración del servidor RADIUS y verificación de secretos"
            },
            tacacs: {
                title: "TACACS+",
                subtitle: "Verificación de servidores de autenticación TACACS+"
            },
            check: "Verificar usuarios",
            noData: "No hay datos de usuario",
            weakPasswords: "Contraseñas débiles detectadas",
            secure: "Todos los usuarios están seguros",
            remediate: "Remediar usuarios"
        },
        // Analytics
        analytics: {
            title: "Analítica e informes",
            subtitle: "Información global de seguridad y métricas de rendimiento de firewalls",
            globalOverview: "Vista general de seguridad global",
            securityScores: "Puntuaciones de seguridad de firewalls",
            moduleDistribution: "Distribución del estado de módulos",
            ranking: "Clasificación de seguridad de firewalls",
            totalFirewalls: "Total de firewalls",
            averageScore: "Puntuación de seguridad promedio",
            goodStatus: "Estado bueno",
            warningStatus: "Estado de advertencia",
            criticalStatus: "Estado crítico",
            inMonitoring: "En monitoreo",
            acrossAll: "En todos los dispositivos",
            ofTotal: "del total",
            displayingAll: "Mostrando todos los",
            scrollMore: "firewalls (desplácese para ver más)",
            resolved: "resueltos"
        },
        // Audit Dashboard
        audit: {
            title: "Auditoría de seguridad",
            analyzing: "Analizando módulos de seguridad...",
            securityAnalysis: "Análisis de seguridad",
            pointsEarned: "Puntos de seguridad obtenidos",
            resolved: "Resuelto",
            atRisk: "En riesgo",
            modulesOverview: "Vista general de módulos de seguridad",
            noIssues: "No se detectaron problemas",
            issuesDetected: "Problemas detectados",
            notChecked: "No verificado",
            timerActive: "Temporizador activo - Pendiente"
        },
        // Status messages
        status: {
            testSuccess: "Prueba de conexión exitosa",
            testFailed: "Prueba de conexión fallida",
            firewallAdded: "Firewall añadido con éxito",
            firewallUpdated: "Firewall actualizado con éxito",
            firewallDeleted: "Firewall eliminado con éxito",
            remediationStarted: "Remediación iniciada",
            remediationComplete: "Remediación completada con éxito",
            remediationFailed: "Remediación fallida",
            checkComplete: "Verificación de seguridad completada"
        }
    },
    it: {
        // Sidebar
        sidebar: {
            title: "SonicWall Backup Incident Manager",
            firewalls: "Firewall",
            wanManagement: "Gestione WAN",
            localUsers: "Utenti Locali",
            ldap: "LDAP",
            radius: "RADIUS",
            tacacs: "TACACS+",
            sso: "SSO",
            ipsecVpn: "VPN IPSec",
            sslVpn: "VPN SSL",
            pppoe: "PPPoE/PPTP/L2TP",
            cse: "CSE",
            analytics: "Analitica"
        },
        // Header
        header: {
            title: "Gestione Firewall",
            total: "Totale",
            connected: "Connessi",
            issues: "Problemi",
            resolved: "Risolti"
        },
        // Disclaimer
        disclaimer: {
            title: "Esclusione di responsabilità:",
            text: "Questo NON è uno strumento ufficiale SonicWall. Questa applicazione viene fornita così com'è solo per scopi di gestione. L'utente si assume tutta la responsabilità per il suo utilizzo. Seguire sempre le migliori pratiche di sicurezza e eseguire il backup delle configurazioni.",
            contact: "Per problemi o richieste di funzionalità, contattare"
        },
        // Common
        common: {
            add: "Aggiungi",
            edit: "Modifica",
            delete: "Elimina",
            save: "Salva",
            cancel: "Annulla",
            test: "Test",
            audit: "Audit",
            refresh: "Aggiorna tutto",
            clearAll: "Cancella tutto",
            name: "Nome",
            ip: "Indirizzo IP",
            username: "Nome utente",
            password: "Password",
            status: "Stato",
            actions: "Azioni",
            search: "Cerca firewall...",
            noResults: "Nessun risultato trovato",
            loading: "Caricamento...",
            error: "Errore",
            success: "Successo"
        },
        // Firewall Management
        firewalls: {
            title: "Firewall",
            subtitle: "Gestisci i tuoi dispositivi SonicWall",
            addFirewall: "Aggiungi Firewall",
            noFirewalls: "Nessun firewall aggiunto",
            addFirst: "Aggiungi il tuo primo firewall usando il modulo sopra",
            apiUrl: "URL dell'API",
            lastChecked: "Ultimo controllo",
            connected: "Connesso",
            disconnected: "Disconnesso",
            testing: "Test in corso"
        },
        // Submenu
        submenu: {
            monitoring: "Monitoraggio",
            remediation: "Rimedio"
        },
        // WAN Management
        wan: {
            title: "Gestione WAN",
            subtitle: "Regole di gestione WAN-to-WAN e rimedio di sicurezza",
            check: "Verifica gestione WAN",
            noData: "Nessun dato di gestione WAN",
            autoLoading: "Caricamento automatico delle regole di gestione WAN...",
            noRules: "Nessuna regola di gestione WAN trovata",
            rulesFound: "Regole di gestione WAN rilevate",
            secure: "Nessuna zona WAN nella gestione",
            atRisk: "Zone WAN trovate nella gestione",
            remediate: "Avvia rimedio WAN",
            remediating: "Rimediando...",
            resolved: "Risolto",
            issues: "Problemi rilevati"
        },
        // SSO
        sso: {
            title: "SSO (Single Sign-On)",
            subtitle: "Monitoraggio e rimedio dell'autenticazione SSO",
            check: "Verifica SSO",
            noData: "Nessun dato SSO",
            enabled: "SSO abilitato",
            disabled: "SSO disabilitato",
            secure: "Metodo di autenticazione sicuro",
            weak: "Metodo di autenticazione debole rilevato",
            remediate: "Rimediare SSO"
        },
        // CSE
        cse: {
            title: "Cloud Secure Edge (CSE)",
            subtitle: "Connettori e configurazione Cloud Secure Edge",
            check: "Verifica CSE",
            noData: "Nessun dato CSE",
            enabled: "CSE abilitato",
            disabled: "CSE disabilitato",
            remediate: "Avvia rimedio CSE",
            reactivate: "Riattiva CSE ora",
            manualSteps: "Nota importante sul rimedio",
            step1: "Accedi a MySonicWall",
            step2: "Vai alla pagina Prodotti e seleziona il Tenant",
            step3: "Seleziona il numero di serie per Cloud Secure Edge",
            step4: "Fai clic su 'Connessione Firewall'",
            step5: "Rimuovi l'associazione facendo clic sull'icona del cestino",
            timerText: "Dopo aver completato i passaggi manuali, verrà avviato un timer di 30 secondi",
            waiting: "In attesa di riattivazione"
        },
        // VPN
        vpn: {
            ssl: {
                title: "VPN SSL",
                subtitle: "Verifica certificati e autenticazione VPN SSL"
            },
            ipsec: {
                title: "VPN IPSec",
                subtitle: "Validazione chiavi pre-condivise e certificati VPN IPSec"
            },
            check: "Verifica VPN",
            noData: "Nessun dato VPN",
            secure: "Configurazione VPN sicura",
            issues: "Problemi di configurazione VPN rilevati",
            remediate: "Rimediare VPN"
        },
        // Users
        users: {
            local: {
                title: "Utenti locali",
                subtitle: "Account utenti locali e rilevamento password deboli"
            },
            ldap: {
                title: "LDAP",
                subtitle: "Configurazione server LDAP e validazione certificati"
            },
            radius: {
                title: "RADIUS",
                subtitle: "Configurazione server RADIUS e verifica segreti"
            },
            tacacs: {
                title: "TACACS+",
                subtitle: "Verifica server di autenticazione TACACS+"
            },
            check: "Verifica utenti",
            noData: "Nessun dato utente",
            weakPasswords: "Password deboli rilevate",
            secure: "Tutti gli utenti sono sicuri",
            remediate: "Rimediare utenti"
        },
        // Analytics
        analytics: {
            title: "Analitica e report",
            subtitle: "Informazioni globali sulla sicurezza e metriche prestazioni firewall",
            globalOverview: "Panoramica globale della sicurezza",
            securityScores: "Punteggi di sicurezza firewall",
            moduleDistribution: "Distribuzione stato moduli",
            ranking: "Classifica sicurezza firewall",
            totalFirewalls: "Totale firewall",
            averageScore: "Punteggio di sicurezza medio",
            goodStatus: "Stato buono",
            warningStatus: "Stato di avviso",
            criticalStatus: "Stato critico",
            inMonitoring: "In monitoraggio",
            acrossAll: "Su tutti i dispositivi",
            ofTotal: "del totale",
            displayingAll: "Visualizzazione di tutti i",
            scrollMore: "firewall (scorri per vedere di più)",
            resolved: "risolti"
        },
        // Audit Dashboard
        audit: {
            title: "Audit di sicurezza",
            analyzing: "Analisi moduli di sicurezza...",
            securityAnalysis: "Analisi di sicurezza",
            pointsEarned: "Punti di sicurezza guadagnati",
            resolved: "Risolto",
            atRisk: "A rischio",
            modulesOverview: "Panoramica moduli di sicurezza",
            noIssues: "Nessun problema rilevato",
            issuesDetected: "Problemi rilevati",
            notChecked: "Non verificato",
            timerActive: "Timer attivo - In attesa"
        },
        // Status messages
        status: {
            testSuccess: "Test di connessione riuscito",
            testFailed: "Test di connessione fallito",
            firewallAdded: "Firewall aggiunto con successo",
            firewallUpdated: "Firewall aggiornato con successo",
            firewallDeleted: "Firewall eliminato con successo",
            remediationStarted: "Rimedio avviato",
            remediationComplete: "Rimedio completato con successo",
            remediationFailed: "Rimedio fallito",
            checkComplete: "Verifica di sicurezza completata"
        }
    }
};

// Function to get nested translation
function getTranslation(key, lang = 'en') {
    const keys = key.split('.');
    let value = translations[lang];
    
    for (const k of keys) {
        if (value && typeof value === 'object') {
            value = value[k];
        } else {
            return key; // Return key if translation not found
        }
    }
    
    return value || key;
}

// Function to change language
function changeLanguage(lang) {
    // Save to localStorage
    localStorage.setItem('selectedLanguage', lang);
    
    // Update all elements with data-i18n attribute
    document.querySelectorAll('[data-i18n]').forEach(element => {
        const key = element.getAttribute('data-i18n');
        const translation = getTranslation(key, lang);
        
        if (element.tagName === 'INPUT' && element.hasAttribute('placeholder')) {
            element.placeholder = translation;
        } else {
            element.textContent = translation;
        }
    });
    
    // Trigger a custom event for dynamic content
    window.dispatchEvent(new CustomEvent('languageChanged', { detail: { lang } }));
}

// Initialize language on page load
function initLanguage() {
    const savedLang = localStorage.getItem('selectedLanguage') || 'en';
    const select = document.getElementById('language-select');
    if (select) {
        select.value = savedLang;
        changeLanguage(savedLang);
    }
}

// Export for use in HTML
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { translations, getTranslation, changeLanguage, initLanguage };
}

