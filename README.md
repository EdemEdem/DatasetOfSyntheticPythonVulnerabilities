# DatasetOfSyntheticPythonVulnerabilities

How to prepare the prerequisits for the analysis:
- STEP 1.1: Preparing the CodeQL artifact
    
    - Install CodeQL's bundled cli tool:
        - You should download the CodeQL bundle from https://github.com/github/codeql-action/releases. The bundle contains:
            - CodeQL CLI product
            - A compatible version of the queries and libraries from https://github.com/github/codeql
            - Precompiled versions of all the queries included in the bundle
            
            - After installing you should be ready to go
                - You can run these commands to verify codeql resolve languages and codeql resolve packs
                - You can see the expected result in the guide linked to bellow
    - A complete guide on installing codeql can be found at: https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/setting-up-the-codeql-cli
    
    - Prepare the codeQL tool for runs with this pipeline: 
        - In the installed directory for codeql - create a custom query dir in at the location: codeql/qlpacks/codeql/python-queries/1.6.6/[myCustomqueryDir]
        - In config.py: set CODEQL_LOCAL_CUSTOM_DIR to the absolute path to the directory you created
        - Make CodeQL available on path

- STEP 1.2: Create codecql databases of
    - You should have CodeQL available on path for this
    - If running on the synthetic dataset you can run the run_all module with the flags --simulate_runs --create_missing_dbs
        - Run from the projects root dir with python -m src.run_all --simulate_runs --create_missing_dbs
        - This will automatically create the codeql databases for each project in the synthetic dataset.
        
- STEP 2: Ready the LLM for prompting.
    - Ensure that the flag ENABLE_DYNAMIC_MODEL_LOADING in src/CONFIG is set to True
    - For the model you're going to run you have to create a file at src/models/[model-name].py
        - In this file there has to be a class that inherits from LLMInterface e.g: class DeepseekReasoner(LLMInterface)
        - Create a method in this class called generate_response(), ensure that this method returns valid JSON
        
        - I have used systems prompts, but I haven't gotten to implement funcitonality so that the system prompt can be taken as an argument in teh generate_response methods. I'll get to this shortly. Let me know if you need it urgently. 
        - If you have any other trouble also let me know


STEP 3.1: How to run the pipeline (If you want to run the pipeline on all files follow Step 2.2)
- The file project_analyzer is responsible for analyzing a project
- Set the following values:
    - path to the project root
    - path to the projects CodeQL Database

STEP 3.2: How to anaylyze all projects in the synthetic dataset:
- The script run_all.py loops through all projects and analyzes them with the pipeline
- Results are written to the directory projects_cleaned
- The script assumes that the CodeQL databases are stroed in the filstructure that you created at STEP 1.2


STEP 3.3: analyzing results and creating metrics