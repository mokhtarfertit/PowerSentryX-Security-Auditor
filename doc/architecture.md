                       PowerSentryX
                            │
                            ▼
                         Launcher
                            │
                            ▼
                     Main Controller
                            │
          ┌─────────────────┴──────────────────┐
          │                                    │
          ▼                                    ▼
       COLLECTORS                           MONITORING
          │                                    │
          │                                    │
   ┌──────┼───────────┐               ┌────────┼──────────┐
   │      │           │               │        │          │
 System Firewall   Defender        Firewall  Defender    EventLog
 Users  Network    Processes       Monitor   Monitor     Monitor
 Services Tasks                   Users     Services
   │                                  │
   └──────────────┬───────────────────┘
                  │
                  ▼
             ANALYSIS ENGINE
                  │
          ┌───────┼────────┐
          │       │        │
      Classifier Analyzer Comparator
          │       │        │
          └───────┼────────┘
                  │
                  ▼
            INFO / WARNING /
               CRITICAL
                  │
             ┌────┴────┐
             │         │
             ▼         ▼
           Logs      Reports