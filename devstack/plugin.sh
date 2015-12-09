# Devstack Plugin for Romana.

ROMANA_DIR=$dir
source $ROMANA_DIR/devstack/lib/romana

# Check for service enabled
if is_service_enabled romana; then
    if [[ "$1" == "source" ]]; then
        echo_summary "Initial source of romana lib script"
    fi

    if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
        # Set up system services
        echo_summary "Configuring system services romana"
        pre_install_romana

    elif [[ "$1" == "stack" && "$2" == "install" ]]; then
        # Perform installation of service source
        echo_summary "Installing romana"
        install_romana

    elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
        # Configure after the other layer 1 and 2 services have been configured
        echo_summary "Configuring romana"
        configure_romana

    elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
        # Initialize and start the romana service
        echo_summary "Initializing romana"
        init_romana
    fi

    if [[ "$1" == "unstack" ]]; then
        # Shut down romana services
        echo_summary "Shutdown romana"
        shutdown_romana
    fi

    if [[ "$1" == "clean" ]]; then
        # Remove state and transient data
        # Remember clean.sh first calls unstack.sh
        echo_summary "Cleanup romana"
        cleanup_romana
    fi
fi
