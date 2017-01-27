{
  global:
    # Export GVR APIs, both public and private.
    gvr_*;

    # Whitelist of DVR APIs required by VrCore for Ambrosia controller support.
    dvrPoseCreate;
    dvrPoseDestroy;
    dvrPoseGet;
    dvrPoseGetController;
    dvrPoseGetVsyncCount;

  local:
    # Hide everything else.
    *;
};
