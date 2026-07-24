from spyscan.collectors.autoruns import AutorunsCollector
from spyscan.collectors.autostart_native import AutostartNativeCollector
from spyscan.collectors.processes import ProcessesCollector
from spyscan.collectors.netconns import NetconnsCollector
from spyscan.collectors.consentstore import ConsentStoreCollector
from spyscan.collectors.services_tasks import ServicesTasksCollector
from spyscan.collectors.drivers import DriversCollector
from spyscan.collectors.canary import CanaryCollector

# Every collector is a Collector instance; collect_all runs c.collect(ctx).
# Append each new collector (as an instance) here.
# autostart_native is the shipped-default autostart source (no bundled Sysinternals
# binary); autoruns runs the fuller sweep only when a user-installed autorunsc is found,
# and autostart_native steps aside then -- so the two never double-report.
COLLECTORS = [AutorunsCollector(), AutostartNativeCollector(), ProcessesCollector(),
              NetconnsCollector(), ConsentStoreCollector(), ServicesTasksCollector(),
              DriversCollector(), CanaryCollector()]
