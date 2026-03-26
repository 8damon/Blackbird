# Runbooks

## IOCTL Capture (Targeted Pull)

1. Build and install the driver.
2. Build `BlackbirdSensorCore` and `BlackbirdInterface`.
3. Run the interface and attach to the target PID.
4. Review the Events and API views.

## ETW Capture (Real-Time)

1. Build `BlackbirdSensorCore` and `BlackbirdInterface`.
2. Run the interface and inspect the ETW pane or ETW inspector.
3. If you only need typed detections, use `SwkStartDetectionEtwSession` in your own consumer.
4. Stop capture from the interface or close the session.

## Validation Suite

1. Build `BlackbirdSensorCore` and `BlackbirdTestSuite`.
2. Run: `BlackbirdTestSuite.exe`
3. Verify all tests pass.

