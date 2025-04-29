# AI-Driven Realistic Event Log Generator

**Project Overview**

The AI-Driven Realistic Event Log Generator is a sophisticated tool engineered to produce synthetic, yet remarkably authentic, event logs tailored to user-defined IT scenarios. By integrating Artificial Intelligence (AI) with the capabilities of Python libraries, this project effectively simulates log data from a diverse range of systems, including Linux, Windows, Apache, Firewalls, DNS servers, VPN gateways, databases, and web applications. The generated logs serve as an invaluable resource for testing, training, and in-depth log analysis.

## Key Features

- **Realistic Log Generation**: Utilizes the `Faker` library to synthesize a diverse range of realistic, system-like data, accurately replicating real-world log entries from various systems and services such as operating systems, web servers, firewalls, VPNs, and databases.
  
- **AI-Enhanced Scenario Matching**: Leverages a pre-trained language model (`sentence-transformers`) to intelligently match user-provided descriptions with predefined event scenarios, ensuring that the logs generated align with the user's intentions based on nuanced semantic similarity, rather than simple keyword matching.

- **Extensible Event Repository**: Features an easily extendable and customizable repository (`EVENTS_DB`) of predefined event scenarios, allowing users to seamlessly add new log types, events, or integrate additional systems, enabling quick adaptation to new use cases or environments.

- **Comprehensive System and Service Support**: Designed to generate logs for a wide range of operating systems (Linux, Windows) and services (Apache, Firewalls, VPNs, DNS, databases, and more), ensuring full compatibility with a broad spectrum of environments.

- **Advanced Matching Sensitivity Control**: Provides users with granular control over the AI matching process. Selectable `strict` or `loose` criteria allow for precise tuning of how the description is matched to event scenarios, making it suitable for both highly specific logs and broader, more general scenarios.

- **Customizable Event Attributes**: Supports fine-tuning of log attributes like timestamps, event severity levels (e.g., INFO, WARN, ERROR), source IP addresses, and user agent strings, allowing users to generate logs with a high level of authenticity and realism based on specific needs.

- **Multi-Scenario Log Generation**: Enables the creation of multiple logs across different scenarios in one execution, enhancing efficiency when simulating diverse environments or security incidents. Logs can be generated in bulk, based on user-defined parameters.

- **Convenient Log Output**: Automatically saves generated logs to a user-specified file (`ai_generated_logs.log`), providing an easily accessible output that can be used directly for testing, analysis, or system integrations. Users can also choose to output logs in different formats, such as CSV or JSON, for compatibility with other tools.

- **Dynamic Time Simulation**: Randomizes log timestamps to simulate events over varying time intervals, offering a more natural sequence of events and supporting testing of systems requiring time-sensitive data, such as SIEM solutions or intrusion detection systems.

- **User-Friendly Interface**: Simplifies the log generation process with an interactive command-line interface (CLI), guiding users through the description input, sensitivity settings, and log generation, making it accessible for both technical and non-technical users.


**Getting Started**

1.  **Install Dependencies**
    Ensure all necessary dependencies are installed by executing the following command:
    ```bash
    pip install sentence-transformers scikit-learn faker numpy
    ```

2.  **Run the Script**
    Initiate the log generation process by running the script:
    ```bash
    python log_generator.py
    ```

3.  **Provide Scenario Description**
    When prompted, enter a concise description of the log scenario you wish to simulate. For example:
    ```
    Failed SSH login attempt from an unknown IP address
    ```

4.  **Set Matching Sensitivity (Optional)**
    Choose between `strict` or `loose` matching sensitivity to fine-tune the scenario matching. Leaving this field blank will default to `loose`, which prioritizes keyword matching.

5.  **Specify Number of Logs**
    Indicate the desired quantity of log entries to be generated for the specified scenario.

6.  **Retrieve Logs**
    The generated log data will be automatically saved to a file named `ai_generated_logs.log`, ready for immediate utilization.

**Use Cases**

* **SIEM Testing:** Simulate a diverse range of system events for rigorous testing of Security Information and Event Management (SIEM) systems.
* **Incident Response Training:** Develop realistic scenarios for training security teams in effective log analysis and incident management protocols.
* **Log Analysis Tool Development:** Facilitate the development and testing of advanced log analysis tools, sophisticated anomaly detection algorithms, and robust log parsers.
* **Test Data Creation:** Generate authentic-looking data for comprehensive testing of systems, applications, and critical network services.
* **Security Training:** Educate system administrators and security analysts on the crucial skills of identifying and responding to various types of system logs.

**Dependencies**

* `sentence-transformers`: Employed for encoding textual data and computing semantic similarity scores.
* `scikit-learn`: Provides the `cosine_similarity` function for precise comparison of user descriptions with predefined event scenarios.
* `faker`: Generates a wide spectrum of realistic synthetic data, including IP addresses, usernames, error messages, and more.
* `numpy`: Handles essential numerical operations required for random data generation processes.
* `random`: Utilized for generating random values such as network ports, event categories, and precise timestamps.
* `datetime`, `timedelta`: Manages intricate date and time manipulations for accurate log generation.
* `time`: Introduces subtle random delays between the generation of individual log entries, contributing to a more natural and realistic log stream.

**Contributing**

We enthusiastically welcome contributions to this project! If you possess innovative ideas for new functionalities, potential enhancements, or critical bug fixes, we encourage you to fork the repository and submit a well-documented pull request.
